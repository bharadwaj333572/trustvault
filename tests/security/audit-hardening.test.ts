import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { db, rawClient, schema } from '@/server/db';
import { eq, desc, asc, gte } from 'drizzle-orm';
import {
  logAuditEvent,
  verifyChain,
  createCheckpoint,
  sanitizeLogString,
  sanitizeLogDetails,
  signCheckpoint,
} from '@/server/services/audit';
import fs from 'fs';
import path from 'path';

describe('PHASE A: Audit Hardening & Cryptographic Integrity', () => {
  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();
  });

  describe('1. Truncation and Anchor (Tail Row Deletion Detection)', () => {
    it('detects deleted tail rows when compared against a signed checkpoint', async () => {
      // 1. Initial verification must pass
      const initialVerify = await verifyChain();
      expect(initialVerify.valid).toBe(true);

      const liveHeadSeq = initialVerify.lastVerifiedSequence;

      // 2. Fetch the tip hash
      const [tipRow] = await db
        .select()
        .from(schema.auditLogs)
        .where(eq(schema.auditLogs.sequenceNumber, liveHeadSeq));

      // 3. Anchor this point with a signed checkpoint
      const checkpoint = await createCheckpoint(liveHeadSeq, tipRow.rowHash, 'EXTERNAL');
      expect(checkpoint).toBeDefined();
      expect(checkpoint.sequenceNumber).toBe(liveHeadSeq);

      // 4. Attacker attempts tail truncation: deletes the latest row using raw SQL bypassing normal flows
      // Note: Triggers protect the table from standard DELETE, so we simulate an attacker with direct DB access
      // who temporarily disables triggers to truncate the tail:
      if ('exec' in (rawClient as any)) {
        await (rawClient as any).exec('DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_logs;');
        await (rawClient as any).exec(`DELETE FROM audit_logs WHERE sequence_number = ${liveHeadSeq};`);
        // Re-enable trigger
        await (rawClient as any).exec(`
          CREATE TRIGGER audit_log_no_delete
          BEFORE DELETE ON audit_logs
          FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
        `);
      } else {
        await (rawClient as any).query('DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_logs;');
        await (rawClient as any).query(`DELETE FROM audit_logs WHERE sequence_number = ${liveHeadSeq};`);
        await (rawClient as any).query(`
          CREATE TRIGGER audit_log_no_delete
          BEFORE DELETE ON audit_logs
          FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
        `);
      }

      // 5. verifyChain() must catch the truncation!
      const verifyAfterTruncation = await verifyChain();
      expect(verifyAfterTruncation.valid).toBe(false);
      expect(verifyAfterTruncation.truncated).toBe(true);
      expect(verifyAfterTruncation.reason).toContain(`TRUNCATED: expected #${liveHeadSeq}, found #${liveHeadSeq - 1}`);

      // 6. Clean up: restore database integrity for subsequent tests
      await runMigrations();
      await seedDatabase();
    });

    it('rejects checkpoint with invalid HMAC signature', async () => {
      // Insert forged checkpoint
      const fakeId = 'forged-checkpoint-id';
      await db.insert(schema.chainCheckpoints).values({
        id: fakeId,
        sequenceNumber: 999999,
        chainHeadHash: '0000000000000000000000000000000000000000000000000000000000000000',
        checkpointType: 'EXTERNAL',
        hmacSignature: 'invalid-forged-signature',
        createdAt: new Date(),
      });

      const verifyRes = await verifyChain();
      expect(verifyRes.valid).toBe(false);
      expect(verifyRes.reason).toContain('CHECKPOINT_SIGNATURE_INVALID');

      // Remove the forged checkpoint
      await db.delete(schema.chainCheckpoints).where(eq(schema.chainCheckpoints.id, fakeId));
    });
  });

  describe('2. Concurrency: 50 Parallel Writes', () => {
    it('maintains a strictly continuous, 100% valid hash chain under 50 concurrent writes', async () => {
      const NUM_CONCURRENT_WRITES = 50;

      // Record baseline count
      const baselineVerify = await verifyChain();
      const startingCount = baselineVerify.totalEntries;

      // Launch 50 concurrent async audit write operations simultaneously
      const writePromises = Array.from({ length: NUM_CONCURRENT_WRITES }).map((_, index) => {
        return logAuditEvent({
          actorEmail: `concurrent.user.${index}@trustvault.test`,
          action: 'CONCURRENT_STRESS_TEST',
          outcome: 'ALLOWED',
          details: { threadIndex: index, batchId: 'batch-50-threads' },
        });
      });

      const results = await Promise.all(writePromises);
      expect(results.length).toBe(NUM_CONCURRENT_WRITES);

      // Verify that all 50 entries received unique sequence numbers and hashes
      const sequenceNumbers = results.map((r) => r.sequenceNumber);
      const uniqueSequences = new Set(sequenceNumbers);
      expect(uniqueSequences.size).toBe(NUM_CONCURRENT_WRITES);

      // Run cryptographic chain verification across all blocks
      const postVerify = await verifyChain();
      expect(postVerify.valid).toBe(true);
      expect(postVerify.totalEntries).toBe(startingCount + NUM_CONCURRENT_WRITES);
    });
  });

  describe('3. Privilege Separation & Append-Only Triggers', () => {
    it('strictly forbids UPDATE operations on audit_logs table via database trigger', async () => {
      const [firstRow] = await db
        .select()
        .from(schema.auditLogs)
        .orderBy(asc(schema.auditLogs.sequenceNumber))
        .limit(1);

      expect(firstRow).toBeDefined();

      // Attempt UPDATE - MUST throw exception from prevent_audit_mutation()
      let updateError: any = null;
      try {
        await db
          .update(schema.auditLogs)
          .set({ action: 'TAMPERED_ACTION' })
          .where(eq(schema.auditLogs.sequenceNumber, firstRow.sequenceNumber));
      } catch (err: any) {
        updateError = err;
      }

      expect(updateError).toBeDefined();
      expect(updateError.message).toMatch(/The audit_logs table is append-only/);
    });

    it('strictly forbids DELETE operations on audit_logs table via database trigger', async () => {
      const [firstRow] = await db
        .select()
        .from(schema.auditLogs)
        .orderBy(asc(schema.auditLogs.sequenceNumber))
        .limit(1);

      let deleteError: any = null;
      try {
        await db
          .delete(schema.auditLogs)
          .where(eq(schema.auditLogs.sequenceNumber, firstRow.sequenceNumber));
      } catch (err: any) {
        deleteError = err;
      }

      expect(deleteError).toBeDefined();
      expect(deleteError.message).toMatch(/The audit_logs table is append-only/);
    });
  });

  describe('4. Log-Injection and Metadata Sanitization', () => {
    it('sanitizes CRLF and control characters from audit metadata', () => {
      const maliciousPayload = 'UPLOAD_DOCUMENT\r\n2026-10-24 12:00:00 [FORGED_LOG_ENTRY] outcome=ALLOWED\x00';
      const sanitized = sanitizeLogString(maliciousPayload);

      expect(sanitized).not.toContain('\r');
      expect(sanitized).not.toContain('\n');
      expect(sanitized).not.toContain('\x00');
    });

    it('sanitizes nested JSON details payload against newline injection', async () => {
      const injectionAttempt = {
        fileName: 'contract.pdf\r\nADMIN_ELEVATION_INJECTED',
        userNotes: 'Legit notes\nINJECTED_SECOND_LINE',
        nested: {
          key: 'evil\x1fvalue',
        },
      };

      const cleanDetails = sanitizeLogDetails(injectionAttempt);
      expect(cleanDetails?.fileName).not.toContain('\r');
      expect(cleanDetails?.fileName).not.toContain('\n');
      expect(cleanDetails?.userNotes).not.toContain('\n');
      expect(cleanDetails?.nested?.key).not.toContain('\x1f');

      // Writing with malicious strings must not corrupt chain integrity
      const logged = await logAuditEvent({
        action: 'INJECTION_TEST\r\nEVIL',
        outcome: 'ALLOWED',
        details: injectionAttempt,
        reason: 'Reason\nwith\nnewlines',
      });

      const [storedRow] = await db
        .select()
        .from(schema.auditLogs)
        .where(eq(schema.auditLogs.id, logged.id));

      expect(storedRow.action).not.toContain('\n');
      expect(storedRow.reason).not.toContain('\n');

      // Chain must remain 100% valid
      const verifyRes = await verifyChain();
      expect(verifyRes.valid).toBe(true);
    });
  });

  describe('5. Audit Completeness: Mandatory Route Audit Registry', () => {
    // Registry of all mutating and file-reading routes and their audited action names
    const AUDITED_ROUTES_REGISTRY: Record<string, { methods: string[]; auditedActions: string[] }> = {
      'api/auth/login': {
        methods: ['POST'],
        auditedActions: ['auth.login_success', 'auth.login_failed', 'LOGIN_SUCCESS', 'LOGIN_FAILURE'],
      },
      'api/auth/logout': {
        methods: ['POST'],
        auditedActions: ['auth.logout', 'LOGOUT'],
      },
      'api/auth/sessions': {
        methods: ['DELETE'],
        auditedActions: ['SESSIONS_REVOKED_OTHERS'],
      },
      'api/auth/password': {
        methods: ['POST'],
        auditedActions: ['PASSWORD_CHANGE', 'PASSWORD_CHANGE_FAILURE', 'auth.password_changed'],
      },
      'api/documents': {
        methods: ['POST'],
        auditedActions: ['document.upload', 'UPLOAD'],
      },
      'api/documents/bulk': {
        methods: ['POST'],
        auditedActions: ['EDIT', 'DELETE', 'softDeleteDocument'],
      },
      'api/documents/[id]': {
        methods: ['PATCH', 'DELETE'],
        auditedActions: ['document.edit', 'document.delete', 'EDIT', 'DELETE', 'DENIED_ATTEMPT'],
      },
      'api/documents/[id]/download': {
        methods: ['GET'],
        auditedActions: ['document.download', 'DOWNLOAD', 'DENIED_ATTEMPT'],
      },
      'api/documents/[id]/restore': {
        methods: ['POST'],
        auditedActions: ['document.restore', 'RESTORE', 'DENIED_ATTEMPT'],
      },
      'api/documents/[id]/grants': {
        methods: ['POST'],
        auditedActions: ['grant.created', 'GRANT', 'DENIED_ATTEMPT'],
      },
      'api/documents/[id]/grants/[grantId]': {
        methods: ['DELETE'],
        auditedActions: ['grant.revoked', 'REVOKE', 'DENIED_ATTEMPT'],
      },
      'api/documents/[id]/versions': {
        methods: ['POST'],
        auditedActions: ['document.version_created', 'NEW_VERSION', 'DENIED_ATTEMPT'],
      },
      'api/documents/[id]/versions/[versionId]/restore': {
        methods: ['POST'],
        auditedActions: ['VERSION_RESTORED', 'DENIED_ATTEMPT'],
      },
      'api/admin/users': {
        methods: ['POST'],
        auditedActions: ['user.created', 'USER_CREATE'],
      },
      'api/admin/users/[id]': {
        methods: ['PATCH'],
        auditedActions: ['user.role_changed', 'user.disabled', 'user.enabled', 'ROLE_CHANGE', 'USER_DISABLE'],
      },
      'api/admin/audit/checkpoint/export': {
        methods: ['GET'],
        auditedActions: ['AUDIT_CHECKPOINT_EXPORTED'],
      },
      'api/suggestions': {
        methods: ['GET'],
        auditedActions: ['ai.suggestion_shown', 'SUGGESTION_SHOWN'],
      },
      'api/suggestions/feedback': {
        methods: ['POST'],
        auditedActions: ['ai.suggestion_accepted', 'ai.suggestion_rejected', 'SUGGESTION_ACCEPTED', 'SUGGESTION_REJECTED'],
      },
    };

    it('enforces that all mutating and file-reading API routes are registered for auditing', () => {
      const apiRootDir = path.resolve(__dirname, '../../src/app/api');

      function scanDir(dir: string): string[] {
        let results: string[] = [];
        const list = fs.readdirSync(dir);
        for (const file of list) {
          const filePath = path.join(dir, file);
          const stat = fs.statSync(filePath);
          if (stat && stat.isDirectory()) {
            results = results.concat(scanDir(filePath));
          } else if (file === 'route.ts') {
            results.push(filePath);
          }
        }
        return results;
      }

      const allRouteFiles = scanDir(apiRootDir);

      // Check each route file
      for (const routeFile of allRouteFiles) {
        const fileContent = fs.readFileSync(routeFile, 'utf-8');
        const relativePath = path
          .relative(path.resolve(__dirname, '../../src/app'), path.dirname(routeFile))
          .replace(/\\/g, '/');

        // Check if route has mutating handlers (POST, PATCH, PUT, DELETE) or file reading (download)
        const hasMutatingHandler = /export\s+async\s+function\s+(POST|PATCH|PUT|DELETE)\b/.test(fileContent);
        const isDownloadRoute = relativePath.includes('download');

        if (hasMutatingHandler || isDownloadRoute) {
          // Exclude verify GET/POST trigger which is an internal verification utility
          if (relativePath.includes('admin/audit/verify')) continue;

          const isRegistered = Boolean(AUDITED_ROUTES_REGISTRY[relativePath]);
          expect(
            isRegistered,
            `SECURITY FAILURE: Route "${relativePath}" has mutating or sensitive handlers but is NOT registered in the mandatory AUDITED_ROUTES_REGISTRY!`
          ).toBe(true);

          // Verify that the file content itself imports or calls logAuditEvent or a service that logs audit events
          const logsAuditing =
            fileContent.includes('logAuditEvent') ||
            fileContent.includes('getDocumentWithAuthorization') ||
            fileContent.includes('createDocument') ||
            fileContent.includes('createDocumentGrant') ||
            fileContent.includes('revokeDocumentGrant') ||
            fileContent.includes('getSharingSuggestions') ||
            fileContent.includes('createDocumentVersion') ||
            fileContent.includes('softDeleteDocument') ||
            fileContent.includes('restoreDocument') ||
            fileContent.includes('recordSuggestionFeedback');

          expect(
            logsAuditing,
            `SECURITY FAILURE: Route "${relativePath}" does not invoke any audit logging mechanism!`
          ).toBe(true);
        }
      }
    });
  });
});
