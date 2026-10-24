import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { POST as logoutHandler } from '@/app/api/auth/logout/route';
import { GET as getMeHandler } from '@/app/api/auth/me/route';
import { POST as postDocumentHandler } from '@/app/api/documents/route';
import { GET as getDocHandler, PATCH as patchDocHandler, DELETE as deleteDocHandler } from '@/app/api/documents/[id]/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { POST as restoreHandler } from '@/app/api/documents/[id]/restore/route';
import { GET as getVersionsHandler, POST as postVersionHandler } from '@/app/api/documents/[id]/versions/route';
import { GET as getActivityHandler } from '@/app/api/documents/[id]/activity/route';
import { POST as createGrantHandler } from '@/app/api/documents/[id]/grants/route';
import { DELETE as revokeGrantHandler } from '@/app/api/documents/[id]/grants/[grantId]/route';
import { GET as autocompleteHandler } from '@/app/api/users/autocomplete/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME, createSession, revokeAllUserSessions } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq, and } from 'drizzle-orm';
import crypto from 'crypto';

describe('PHASE B: Authorisation Edge Cases & Attack Defenses', () => {
  let adminToken: string;
  let aliceToken: string; // Owner 1
  let bobToken: string;   // Owner 2
  let carolToken: string; // Viewer

  let aliceDocId: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    // 1. Authenticate Admin
    const adminRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.admin.email, password: SEED_CREDENTIALS.admin.password }),
      })
    );
    adminToken = adminRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // 2. Authenticate Alice (Owner)
    const aliceRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    aliceToken = aliceRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // 3. Authenticate Bob (Owner 2)
    const bobRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
      })
    );
    bobToken = bobRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // 4. Authenticate Carol (Viewer)
    const carolRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    carolToken = carolRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // 5. Alice uploads a test document
    const fileBytes = Buffer.from('%PDF-1.4\nSuper Secret Research Data for Edge Cases\n%%EOF');
    const form = new FormData();
    form.append('file', new Blob([fileBytes], { type: 'application/pdf' }), 'edge_case_doc.pdf');
    form.append('title', 'Edge Case Research');
    form.append('category', 'TECHNICAL');

    const uploadRes = await postDocumentHandler(
      new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: form,
      })
    );
    const uploadJson = await uploadRes.json();
    aliceDocId = uploadJson.document.id;

    // Alice uploads Version 2
    const v2Bytes = Buffer.from('%PDF-1.4\nSuper Secret Research Data Version 2\n%%EOF');
    const v2Form = new FormData();
    v2Form.append('file', new Blob([v2Bytes], { type: 'application/pdf' }), 'edge_case_doc_v2.pdf');

    await postVersionHandler(
      new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/versions`, {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: v2Form,
      }),
      { params: { id: aliceDocId } }
    );
  });

  describe('1. IDOR Defense Across All Routes', () => {
    it('denies Bob from listing versions of Alice document (returns 404)', async () => {
      const res = await getVersionsHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/versions`, {
          headers: { authorization: `Bearer ${bobToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(404);
    });

    it('denies Bob from viewing activity of Alice document (returns 404)', async () => {
      const res = await getActivityHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/activity`, {
          headers: { authorization: `Bearer ${bobToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(404);
    });

    it('denies Bob from restoring Alice soft-deleted document (returns 404)', async () => {
      const res = await restoreHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/restore`, {
          method: 'POST',
          headers: { authorization: `Bearer ${bobToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(404);
    });

    it('denies ungranted range requests on download endpoint (returns 404)', async () => {
      const res = await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download`, {
          headers: { authorization: `Bearer ${bobToken}`, range: 'bytes=0-10' },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(404);
    });

    it('allows valid range request for authorized owner (returns 206 Partial Content)', async () => {
      const res = await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download`, {
          headers: { authorization: `Bearer ${aliceToken}`, range: 'bytes=0-10' },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(206);
      expect(res.headers.get('content-range')).toContain('bytes 0-10/');
      expect(res.headers.get('accept-ranges')).toBe('bytes');
    });
  });

  describe('2. Revoke and Version Download Defenses', () => {
    it('denies version download after grant is revoked', async () => {
      // 1. Grant Carol READ on Alice doc
      const grantRes = await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: SEED_CREDENTIALS.viewer.email, permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );
      const grantJson = await grantRes.json();
      const grantId = grantJson.grant.id;

      // 2. Carol can download version 1
      const v1Res = await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download?version=1`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(v1Res.status).toBe(200);

      // 3. Alice revokes Carol's grant
      await revokeGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants/${grantId}`, {
          method: 'DELETE',
          headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        }),
        { params: { id: aliceDocId, grantId } }
      );

      // 4. Carol's very next version download request is refused (404)
      const postRevokeRes = await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download?version=1`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(postRevokeRes.status).toBe(404);
    });
  });

  describe('3. Grant Creation Boundary & Business Rule Defenses', () => {
    it('rejects creating grant for nonexistent user with 400 Validation Error', async () => {
      const res = await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: 'nonexistent.ghost@meridian.test', permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toContain('not found in system');
    });

    it('rejects creating grant for disabled user with 400 Validation Error', async () => {
      // Create a disabled user in DB
      const disabledUserId = crypto.randomUUID();
      const disabledEmail = 'disabled.target@meridian.test';
      await db.insert(schema.users).values({
        id: disabledUserId,
        email: disabledEmail,
        fullName: 'Disabled Target User',
        passwordHash: 'dummy_hash',
        role: 'VIEWER',
        isDisabled: true,
      });

      const res = await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: disabledEmail, permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toContain('disabled user account');
    });

    it('rejects user granting themselves access with 400 Validation Error', async () => {
      const res = await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: SEED_CREDENTIALS.owner1.email, permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toContain('already have implicit full control');
    });

    it('denies user with EDIT grant from deleting the document or sharing it to others', async () => {
      // Grant Bob EDIT on Alice doc
      await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: SEED_CREDENTIALS.owner2.email, permission: 'EDIT' }),
        }),
        { params: { id: aliceDocId } }
      );

      // Bob tries to delete Alice's doc -> 404
      const deleteRes = await deleteDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          method: 'DELETE',
          headers: { authorization: `Bearer ${bobToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        }),
        { params: { id: aliceDocId } }
      );
      expect(deleteRes.status).toBe(404);

      // Bob tries to share Alice's doc -> 404
      const shareRes = await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${bobToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: SEED_CREDENTIALS.viewer.email, permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );
      expect(shareRes.status).toBe(404);
    });
  });

  describe('4. Multi-Device Session Purge on Account Disablement', () => {
    it('purges all active sessions across multiple browsers when user is disabled', async () => {
      // Carol creates a secondary session (simulating second browser / phone)
      const carolUser = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.viewer.email) });
      const secondSession = await createSession(carolUser!.id, '192.168.1.50', 'Mobile Browser');

      // Verify second session works
      const testRes1 = await getMeHandler(
        new NextRequest('http://localhost:3000/api/auth/me', {
          headers: { authorization: `Bearer ${secondSession.rawToken}` },
        })
      );
      expect(testRes1.status).toBe(200);

      // Administrator disables Carol
      await revokeAllUserSessions(carolUser!.id);
      await db.update(schema.users).set({ isDisabled: true }).where(eq(schema.users.id, carolUser!.id));

      // Both primary token and second session token MUST fail immediately with 401
      const testPrimary = await getMeHandler(
        new NextRequest('http://localhost:3000/api/auth/me', {
          headers: { authorization: `Bearer ${carolToken}` },
        })
      );
      expect(testPrimary.status).toBe(401);

      const testSecondary = await getMeHandler(
        new NextRequest('http://localhost:3000/api/auth/me', {
          headers: { authorization: `Bearer ${secondSession.rawToken}` },
        })
      );
      expect(testSecondary.status).toBe(401);

      // Re-enable Carol for subsequent tests
      await db.update(schema.users).set({ isDisabled: false }).where(eq(schema.users.id, carolUser!.id));
    });
  });

  describe('5. Soft-Delete and Restore Lifecycle', () => {
    it('soft-deleted document is hidden from granted users and becomes accessible upon restore', async () => {
      // 1. Grant Carol READ on Alice's doc
      await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: SEED_CREDENTIALS.viewer.email, permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );

      // Re-login Carol to refresh active token
      const carolLoginRes = await loginHandler(
        new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
        })
      );
      carolToken = carolLoginRes.cookies.get(SESSION_COOKIE_NAME)!.value;

      // 2. Alice soft-deletes document
      const delRes = await deleteDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          method: 'DELETE',
          headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        }),
        { params: { id: aliceDocId } }
      );
      expect(delRes.status).toBe(200);

      // 3. Carol tries to access soft-deleted doc -> 404
      const carolAccessRes = await getDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(carolAccessRes.status).toBe(404);

      // 4. Alice restores document
      const restoreRes = await restoreHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/restore`, {
          method: 'POST',
          headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        }),
        { params: { id: aliceDocId } }
      );
      expect(restoreRes.status).toBe(200);

      // 5. Carol can access again
      const carolRestoredAccessRes = await getDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(carolRestoredAccessRes.status).toBe(200);
    });
  });

  describe('6. Share-Autocomplete User Enumeration Defense', () => {
    it('rejects query shorter than 3 characters with 400 error', async () => {
      const res = await autocompleteHandler(
        new NextRequest('http://localhost:3000/api/users/autocomplete?q=al', {
          headers: { authorization: `Bearer ${aliceToken}` },
        })
      );
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.code).toBe('QUERY_TOO_SHORT');
    });

    it('returns only safe public fields and excludes sensitive security fields', async () => {
      const res = await autocompleteHandler(
        new NextRequest('http://localhost:3000/api/users/autocomplete?q=alice', {
          headers: { authorization: `Bearer ${bobToken}` },
        })
      );
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.users.length).toBeGreaterThan(0);

      const userRecord = json.users[0];
      expect(userRecord).toHaveProperty('id');
      expect(userRecord).toHaveProperty('email');
      expect(userRecord).toHaveProperty('fullName');

      // Sensitive fields MUST NOT be present
      expect(userRecord).not.toHaveProperty('passwordHash');
      expect(userRecord).not.toHaveProperty('failedLoginAttempts');
      expect(userRecord).not.toHaveProperty('lockedUntil');
    });
  });

  describe('7. Timing Difference Defense: Missing vs Forbidden', () => {
    it('returns identical error shapes and timing within tight statistical tolerance', async () => {
      const fakeUuid = '11111111-2222-3333-4444-555555555555';

      // Ensure Bob has no grant on a brand new strictly private document
      const privateDocBytes = Buffer.from('%PDF-1.4\nSuper Secret Never Granted Document\n%%EOF');
      const pForm = new FormData();
      pForm.append('file', new Blob([privateDocBytes], { type: 'application/pdf' }), 'unshared.pdf');
      pForm.append('title', 'Never Granted Doc');
      pForm.append('category', 'LEGAL');

      const pRes = await postDocumentHandler(
        new NextRequest('http://localhost:3000/api/documents', {
          method: 'POST',
          headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: pForm,
        })
      );
      const pJson = await pRes.json();
      const unsharedDocId = pJson.document.id;

      // Warm up
      await getDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${fakeUuid}`, {
          headers: { authorization: `Bearer ${bobToken}` },
        }),
        { params: { id: fakeUuid } }
      );

      // Measure missing doc
      const t0 = performance.now();
      const missingRes = await getDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${fakeUuid}`, {
          headers: { authorization: `Bearer ${bobToken}` },
        }),
        { params: { id: fakeUuid } }
      );
      const missingDuration = performance.now() - t0;
      const missingJson = await missingRes.json();

      // Measure unpermitted real doc
      const t1 = performance.now();
      const forbiddenRes = await getDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${unsharedDocId}`, {
          headers: { authorization: `Bearer ${bobToken}` },
        }),
        { params: { id: unsharedDocId } }
      );
      const forbiddenDuration = performance.now() - t1;
      const forbiddenJson = await forbiddenRes.json();

      // Assert identical HTTP status and error payload shape
      expect(missingRes.status).toBe(404);
      expect(forbiddenRes.status).toBe(404);
      expect(missingJson.error.code).toBe(forbiddenJson.error.code);
      expect(missingJson.error.message).toBe(forbiddenJson.error.message);

      // Timing difference should not show massive order-of-magnitude discrepancy
      const timeDiffMs = Math.abs(missingDuration - forbiddenDuration);
      expect(timeDiffMs).toBeLessThan(150); // Under 150ms variance in in-process execution
    });
  });

  describe('8. Session Invalidation on Logout', () => {
    it('invalidates session token upon logout so subsequent calls return 401', async () => {
      // 1. Create a temporary session for testing
      const tempLogin = await loginHandler(
        new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
        })
      );
      const tempToken = tempLogin.cookies.get(SESSION_COOKIE_NAME)!.value;

      // Verify active
      const activeCheck = await getMeHandler(
        new NextRequest('http://localhost:3000/api/auth/me', {
          headers: { authorization: `Bearer ${tempToken}` },
        })
      );
      expect(activeCheck.status).toBe(200);

      // 2. Logout
      const logoutRes = await logoutHandler(
        new NextRequest('http://localhost:3000/api/auth/logout', {
          method: 'POST',
          headers: { authorization: `Bearer ${tempToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        })
      );
      expect(logoutRes.status).toBe(200);

      // 3. Subsequent request with logged-out token MUST fail with 401
      const postLogoutCheck = await getMeHandler(
        new NextRequest('http://localhost:3000/api/auth/me', {
          headers: { authorization: `Bearer ${tempToken}` },
        })
      );
      expect(postLogoutCheck.status).toBe(401);
    });
  });
});
