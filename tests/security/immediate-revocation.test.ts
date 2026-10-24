import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { POST as postDocumentHandler } from '@/app/api/documents/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { POST as grantHandler } from '@/app/api/documents/[id]/grants/route';
import { DELETE as revokeHandler } from '@/app/api/documents/[id]/grants/[grantId]/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME, revokeAllUserSessions } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';

describe('Requirement 3: Immediate Revocation Security Guarantees', () => {
  let aliceToken: string;
  let carolToken: string;
  let testDocId: string;
  let testGrantId: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    // 1. Authenticate Alice (Owner)
    const aliceRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    aliceToken = aliceRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // 2. Authenticate Carol (Viewer)
    const carolRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    carolToken = carolRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // 3. Alice uploads a test document
    const pdfBytes = Buffer.from('%PDF-1.4\nHighly Confidential Revocation Test File\n%%EOF');
    const formData = new FormData();
    formData.append('file', new Blob([pdfBytes], { type: 'application/pdf' }), 'revocation_test.pdf');
    formData.append('title', 'Revocation Target Document');

    const uploadRes = await postDocumentHandler(
      new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: formData,
      })
    );
    const uploadJson = await uploadRes.json();
    testDocId = uploadJson.document.id;
  });

  it('user downloads successfully -> owner revokes -> same users next request is instantly refused (404)', async () => {
    // Step 1: Alice grants Carol READ permission
    const grantRes = await grantHandler(
      new NextRequest(`http://localhost:3000/api/documents/${testDocId}/grants`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${aliceToken}`,
          'content-type': 'application/json',
          origin: 'http://localhost:3000',
          host: 'localhost:3000',
        },
        body: JSON.stringify({
          targetEmail: SEED_CREDENTIALS.viewer.email,
          permission: 'READ',
        }),
      }),
      { params: { id: testDocId } }
    );
    expect(grantRes.status).toBe(201);
    const grantJson = await grantRes.json();
    testGrantId = grantJson.grant.id;

    // Step 2: Carol downloads successfully
    const download1Res = await downloadHandler(
      new NextRequest(`http://localhost:3000/api/documents/${testDocId}/download`, {
        method: 'GET',
        headers: { authorization: `Bearer ${carolToken}` },
      }),
      { params: { id: testDocId } }
    );
    expect(download1Res.status).toBe(200);
    const text1 = await download1Res.text();
    expect(text1).toContain('Highly Confidential Revocation Test File');

    // Step 3: Alice REVOKES the grant
    const revokeRes = await revokeHandler(
      new NextRequest(`http://localhost:3000/api/documents/${testDocId}/grants/${testGrantId}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
      }),
      { params: { id: testDocId, grantId: testGrantId } }
    );
    expect(revokeRes.status).toBe(200);

    // Step 4: Carol makes the exact same download request on the VERY NEXT millisecond
    const download2Res = await downloadHandler(
      new NextRequest(`http://localhost:3000/api/documents/${testDocId}/download`, {
        method: 'GET',
        headers: { authorization: `Bearer ${carolToken}` },
      }),
      { params: { id: testDocId } }
    );

    // NON-NEGOTIABLE GUARANTEE: The request MUST be rejected immediately (returns uniform 404)
    expect(download2Res.status).toBe(404);
    const download2Json = await download2Res.json();
    expect(download2Json.error.code).toBe('NOT_FOUND');
  });

  it('disabling a user instantly terminates existing sessions and rejects next request', async () => {
    // Carol logs in again to get fresh session
    const carolLoginRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    const freshCarolToken = carolLoginRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Admin disables Carol in database
    const users = await db.select().from(schema.users).where(eq(schema.users.email, SEED_CREDENTIALS.viewer.email));
    const carolUserId = users[0].id;

    await db.update(schema.users).set({ isDisabled: true }).where(eq(schema.users.id, carolUserId));
    await revokeAllUserSessions(carolUserId);

    // Carol attempts to download seed doc 1 (where she was originally granted READ)
    const seedDocs = await db.select().from(schema.documents).where(eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'));
    const seedDocId = seedDocs[0].id;

    const res = await downloadHandler(
      new NextRequest(`http://localhost:3000/api/documents/${seedDocId}/download`, {
        method: 'GET',
        headers: { authorization: `Bearer ${freshCarolToken}` },
      }),
      { params: { id: seedDocId } }
    );

    // Must be rejected with 401 Unauthenticated / disabled
    expect(res.status).toBe(401);
  });
});
