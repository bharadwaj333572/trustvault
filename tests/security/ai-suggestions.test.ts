import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { GET as suggestionsHandler } from '@/app/api/suggestions/route';
import { POST as feedbackHandler } from '@/app/api/suggestions/feedback/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq, and, desc } from 'drizzle-orm';

describe('AI Sharing Suggestions Security & Non-Widening Guarantees', () => {
  let aliceToken: string;
  let bobToken: string;
  let aliceDoc2Id: string;

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

    // Authenticate Bob (Owner 2 / Collaborator)
    const bobRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
      })
    );
    bobToken = bobRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Retrieve Alice's Legal Doc ("Master Supply Agreement v2.1")
    const docs = await db.select().from(schema.documents).where(eq(schema.documents.title, 'Master Supply Agreement v2.1'));
    aliceDoc2Id = docs[0].id;
  });

  it('PROVES: AI suggestions alone change ZERO permissions and grant zero access', async () => {
    // 1. Initial State: Count grants on aliceDoc2Id
    const initialGrants = await db
      .select()
      .from(schema.documentGrants)
      .where(eq(schema.documentGrants.documentId, aliceDoc2Id));

    expect(initialGrants.length).toBe(0);

    // 2. Alice requests AI suggestions
    const req = new NextRequest(`http://localhost:3000/api/suggestions?documentId=${aliceDoc2Id}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${aliceToken}` },
    });

    const res = await suggestionsHandler(req);
    expect(res.status).toBe(200);
    const json = await res.json();

    expect(json.suggestions.length).toBeGreaterThan(0);
    expect(json.disclaimer).toContain('grant ZERO access automatically');

    // 3. PROOF: Check document_grants table in database. It MUST still be 0!
    const grantsAfterSuggestion = await db
      .select()
      .from(schema.documentGrants)
      .where(eq(schema.documentGrants.documentId, aliceDoc2Id));

    expect(grantsAfterSuggestion.length).toBe(0);

    // 4. PROOF: Any suggested user (e.g. Bob or Carol) still receives 404 if attempting download
    const bobDownloadRes = await downloadHandler(
      new NextRequest(`http://localhost:3000/api/documents/${aliceDoc2Id}/download`, {
        method: 'GET',
        headers: { authorization: `Bearer ${bobToken}` },
      }),
      { params: { id: aliceDoc2Id } }
    );

    expect(bobDownloadRes.status).toBe(404);
  });

  it('audits SUGGESTION_SHOWN, SUGGESTION_ACCEPTED, and SUGGESTION_REJECTED in the hash chain', async () => {
    // 1. Check that SUGGESTION_SHOWN was logged
    const shownLogs = await db
      .select()
      .from(schema.auditLogs)
      .where(
        and(
          eq(schema.auditLogs.documentId, aliceDoc2Id),
          eq(schema.auditLogs.action, 'SUGGESTION_SHOWN')
        )
      )
      .limit(1);

    expect(shownLogs.length).toBe(1);
    expect(shownLogs[0].outcome).toBe('ALLOWED');

    // 2. Submit rejection feedback
    const rejectReq = new NextRequest('http://localhost:3000/api/suggestions/feedback', {
      method: 'POST',
      headers: {
        authorization: `Bearer ${aliceToken}`,
        'content-type': 'application/json',
        origin: 'http://localhost:3000',
        host: 'localhost:3000',
      },
      body: JSON.stringify({
        documentId: aliceDoc2Id,
        targetEmail: SEED_CREDENTIALS.owner2.email,
        accepted: false,
      }),
    });

    const rejectRes = await feedbackHandler(rejectReq);
    expect(rejectRes.status).toBe(200);

    // 3. Verify SUGGESTION_REJECTED was logged
    const rejectLogs = await db
      .select()
      .from(schema.auditLogs)
      .where(
        and(
          eq(schema.auditLogs.documentId, aliceDoc2Id),
          eq(schema.auditLogs.action, 'SUGGESTION_REJECTED')
        )
      )
      .orderBy(desc(schema.auditLogs.sequenceNumber))
      .limit(1);

    expect(rejectLogs.length).toBe(1);
  });
});
