import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { db, rawClient, schema } from '@/server/db';
import { logAuditEvent, verifyChain } from '@/server/services/audit';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { eq, desc } from 'drizzle-orm';

describe('Audit Trail: Tamper-Evident Hash Chain & Trigger Guarantees', () => {
  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();
  });

  it('append-only trigger strictly blocks direct SQL UPDATE on audit_logs', async () => {
    // Attempt to update an existing audit log entry
    const updateSql = `UPDATE audit_logs SET outcome = 'ALLOWED' WHERE sequence_number = 1;`;

    let updateFailed = false;
    let errorMessage = '';

    try {
      if ('exec' in (rawClient as any)) {
        await (rawClient as any).exec(updateSql);
      } else {
        await (rawClient as any).query(updateSql);
      }
    } catch (err: any) {
      updateFailed = true;
      errorMessage = err.message;
    }

    expect(updateFailed).toBe(true);
    expect(errorMessage).toMatch(/The audit_logs table is append-only/i);
  });

  it('append-only trigger strictly blocks direct SQL DELETE on audit_logs', async () => {
    const deleteSql = `DELETE FROM audit_logs WHERE sequence_number = 1;`;

    let deleteFailed = false;
    let errorMessage = '';

    try {
      if ('exec' in (rawClient as any)) {
        await (rawClient as any).exec(deleteSql);
      } else {
        await (rawClient as any).query(deleteSql);
      }
    } catch (err: any) {
      deleteFailed = true;
      errorMessage = err.message;
    }

    expect(deleteFailed).toBe(true);
    expect(errorMessage).toMatch(/The audit_logs table is append-only/i);
  });

  it('verifies that the cryptographic hash chain is currently valid', async () => {
    const result = await verifyChain();
    expect(result.valid).toBe(true);
    expect(result.totalEntries).toBeGreaterThan(0);
    expect(result.lastVerifiedSequence).toBeGreaterThan(0);
  });

  it('detects tampering immediately if an entry in the chain is modified', async () => {
    // 1. Temporarily disable the trigger to simulate an offline DB compromise or corrupt disk bit
    const bypassSql = `
      ALTER TABLE audit_logs DISABLE TRIGGER ALL;
      UPDATE audit_logs SET reason = 'TAMPERED_BY_ADVERSARY' WHERE sequence_number = 2;
      ALTER TABLE audit_logs ENABLE TRIGGER ALL;
    `;

    if ('exec' in (rawClient as any)) {
      await (rawClient as any).exec(bypassSql);
    } else {
      await (rawClient as any).query(bypassSql);
    }

    // 2. Run verifyChain()
    const verifyResult = await verifyChain();

    // 3. Chain verification MUST report invalid and pinpoint the compromised block
    expect(verifyResult.valid).toBe(false);
    expect(verifyResult.brokenAtSequence).toBe(2);
    expect(verifyResult.reason).toContain('hash mismatch');

    // 4. Reset database state with clean seed
    await seedDatabase();
    const restoredResult = await verifyChain();
    expect(restoredResult.valid).toBe(true);
  });

  it('records every denied attempt with true security reason and caller metadata', async () => {
    // Carol logs in
    const carolLoginRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    const carolToken = carolLoginRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Bob's classified document
    const bobDocs = await db.select().from(schema.documents).where(eq(schema.documents.title, 'Project Zephyr Hardware Schematics'));
    const bobDocId = bobDocs[0].id;

    // Carol tries to download Bob's document (IDOR attempt)
    const res = await downloadHandler(
      new NextRequest(`http://localhost:3000/api/documents/${bobDocId}/download`, {
        method: 'GET',
        headers: { authorization: `Bearer ${carolToken}` },
      }),
      { params: { id: bobDocId } }
    );
    expect(res.status).toBe(404);

    // Verify audit log captured the denial
    const latestLogs = await db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.documentId, bobDocId))
      .orderBy(desc(schema.auditLogs.sequenceNumber))
      .limit(1);

    expect(latestLogs.length).toBe(1);
    const log = latestLogs[0];
    expect(log.outcome).toBe('DENIED');
    expect(log.action).toBe('DENIED_ATTEMPT');
    expect(log.reason).toBe('NO_ACTIVE_GRANT_FOR_USER');
    expect(log.actorEmail).toBe(SEED_CREDENTIALS.viewer.email);
  });
});
