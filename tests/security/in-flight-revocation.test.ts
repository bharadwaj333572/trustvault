import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { DELETE as revokeGrantHandler } from '@/app/api/documents/[id]/grants/[grantId]/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq, desc } from 'drizzle-orm';

describe('In-Flight Revocation & Chunk-Boundary Re-Authorization', () => {
  let aliceToken: string;
  let carolToken: string;
  let testDocId: string;
  let carolGrantId: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    // Authenticate Alice (Owner)
    const aliceRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    aliceToken = aliceRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Authenticate Carol (Viewer)
    const carolRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    carolToken = carolRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Locate seeded doc granted to Carol (Q3 Financial Audit)
    const seedDocs = await db
      .select()
      .from(schema.documents)
      .where(eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'));
    testDocId = seedDocs[0].id;

    const grants = await db
      .select()
      .from(schema.documentGrants)
      .where(eq(schema.documentGrants.documentId, testDocId));
    carolGrantId = grants[0].id;
  });

  it('successfully streams all chunks when permission remains intact', async () => {
    const req = new NextRequest(`http://localhost:3000/api/documents/${testDocId}/download`, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${carolToken}`,
        'x-test-chunk-size': '24',
      },
    });

    const res = await downloadHandler(req, { params: { id: testDocId } });
    expect(res.status).toBe(200);

    const reader = res.body?.getReader();
    expect(reader).toBeDefined();

    let totalBytesReceived = 0;
    let chunkCount = 0;

    while (reader) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytesReceived += value.length;
      chunkCount += 1;
    }

    expect(totalBytesReceived).toBeGreaterThan(0);
    expect(chunkCount).toBeGreaterThan(1);
  });

  it('aborts download mid-stream at chunk boundary when grant is revoked in flight', async () => {
    // Carol starts a slow stream with small chunk size
    const req = new NextRequest(`http://localhost:3000/api/documents/${testDocId}/download`, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${carolToken}`,
        'x-test-chunk-size': '64',
        'x-test-slow-stream': '20',
      },
    });

    const res = await downloadHandler(req, { params: { id: testDocId } });
    expect(res.status).toBe(200);

    const reader = res.body?.getReader();
    expect(reader).toBeDefined();

    // Read the first chunk successfully
    const firstChunk = await reader!.read();
    expect(firstChunk.done).toBe(false);
    expect(firstChunk.value?.length).toBe(64);

    // Alice revokes Carol's grant while download is in flight!
    const revokeReq = new NextRequest(
      `http://localhost:3000/api/documents/${testDocId}/grants/${carolGrantId}`,
      {
        method: 'DELETE',
        headers: {
          authorization: `Bearer ${aliceToken}`,
          origin: 'http://localhost:3000',
          host: 'localhost:3000',
        },
      }
    );
    const revokeRes = await revokeGrantHandler(revokeReq, {
      params: { id: testDocId, grantId: carolGrantId },
    });
    expect(revokeRes.status).toBe(200);

    // Attempting to read the next chunk MUST fail as the stream is aborted
    let streamAborted = false;
    try {
      await reader!.read();
    } catch (err: any) {
      streamAborted = true;
      expect(err.message).toContain('Authorization revoked in flight');
    }

    expect(streamAborted).toBe(true);

    // Verify audit log has recorded the in-flight abortion
    const abortAudit = await db
      .select()
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.action, 'DOWNLOAD'))
      .orderBy(desc(schema.auditLogs.sequenceNumber))
      .limit(1);

    expect(abortAudit[0].outcome).toBe('DENIED');
    expect(abortAudit[0].reason).toBe('IN_FLIGHT_REVOCATION_ABORTED');
  });
});
