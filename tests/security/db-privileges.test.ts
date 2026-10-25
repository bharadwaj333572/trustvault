import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { GET as getAuditHandler } from '@/app/api/admin/audit/route';
import { GET as checkpointExportHandler } from '@/app/api/admin/audit/checkpoint/export/route';
import { rawClient, db, schema } from '@/server/db';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { eq, desc } from 'drizzle-orm';

describe('Priority 2: Database Privileges, Core Audit Queries & Checkpoint Exports', () => {
  let adminToken: string;
  let testDocId: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    const adminRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.admin.email, password: SEED_CREDENTIALS.admin.password }),
      })
    );
    adminToken = adminRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    const seedDocs = await db
      .select()
      .from(schema.documents)
      .where(eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'));
    testDocId = seedDocs[0].id;
  });

  describe('1. Database Trigger & Mutation Defense', () => {
    it('fails when any app connection attempts to UPDATE an audit row', async () => {
      const auditRows = await db.select().from(schema.auditLogs).limit(1);
      expect(auditRows.length).toBeGreaterThan(0);
      const rowId = auditRows[0].id;

      const updateSql = `UPDATE audit_logs SET outcome = 'DENIED' WHERE id = '${rowId}';`;

      let errorThrown = false;
      try {
        if ('exec' in (rawClient as any)) {
          await (rawClient as any).exec(updateSql);
        } else {
          await (rawClient as any).query(updateSql);
        }
      } catch (err: any) {
        errorThrown = true;
        expect(err.message).toContain('UPDATE and DELETE operations are strictly prohibited');
      }

      expect(errorThrown).toBe(true);
    });

    it('fails when any app connection attempts to DELETE an audit row', async () => {
      const auditRows = await db.select().from(schema.auditLogs).limit(1);
      expect(auditRows.length).toBeGreaterThan(0);
      const rowId = auditRows[0].id;

      const deleteSql = `DELETE FROM audit_logs WHERE id = '${rowId}';`;

      let errorThrown = false;
      try {
        if ('exec' in (rawClient as any)) {
          await (rawClient as any).exec(deleteSql);
        } else {
          await (rawClient as any).query(deleteSql);
        }
      } catch (err: any) {
        errorThrown = true;
        expect(err.message).toContain('UPDATE and DELETE operations are strictly prohibited');
      }

      expect(errorThrown).toBe(true);
    });
  });

  describe('2. The Core Forensic Question: "Who opened document X and when?"', () => {
    it('answers who opened document X and when with a single direct query on seeded data', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/audit?documentId=${testDocId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      const res = await getAuditHandler(req);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(Array.isArray(json.logs)).toBe(true);
      expect(json.logs.length).toBeGreaterThan(0);

      // Verify every returned log entry corresponds strictly to the queried document
      for (const entry of json.logs) {
        expect(entry.documentId).toBe(testDocId);
        expect(entry.createdAt).toBeDefined();
        expect(entry.actorEmail).toBeDefined();
        expect(entry.action).toBeDefined();
        expect(entry.outcome).toBeDefined();
      }

      console.log(`[Core Forensic Audit] Found ${json.logs.length} access records for Document ${testDocId}:`);
      console.log(`- Latest access: ${json.logs[0].actorEmail} (${json.logs[0].action}) at ${json.logs[0].createdAt}`);
    });
  });

  describe('3. External Anchor & Checkpoint Exports', () => {
    it('exports signed checkpoint JSON payload with HMAC signature for WORM archival', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/audit/checkpoint/export', {
        method: 'GET',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      const res = await checkpointExportHandler(req);
      expect(res.status).toBe(200);

      const json = await res.json();
      expect(json.exportedAt).toBeDefined();
      expect(json.anchor).toBeDefined();
      expect(json.anchor.sequenceNumber).toBeDefined();
      expect(json.anchor.chainHeadHash).toBeDefined();
      expect(json.anchor.hmacSignature).toBeDefined();
    });

    it('exports audit stream to standard CSV format with all immutable columns', async () => {
      const req = new NextRequest(`http://localhost:3000/api/admin/audit?documentId=${testDocId}&format=csv`, {
        method: 'GET',
        headers: { authorization: `Bearer ${adminToken}` },
      });

      const res = await getAuditHandler(req);
      expect(res.status).toBe(200);
      expect(res.headers.get('content-type')).toContain('text/csv');

      const csv = await res.text();
      expect(csv).toContain('sequence_number,timestamp,action,outcome,actor_email');
      expect(csv).toContain(testDocId);
    });
  });
});
