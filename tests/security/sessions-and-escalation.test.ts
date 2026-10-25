import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { POST as passwordChangeHandler } from '@/app/api/auth/password/route';
import { GET as getSessionsHandler, DELETE as revokeOtherSessionsHandler } from '@/app/api/auth/sessions/route';
import { POST as createUserHandler } from '@/app/api/admin/users/route';
import { PATCH as patchUserHandler } from '@/app/api/admin/users/[id]/route';
import { POST as createGrantHandler } from '@/app/api/documents/[id]/grants/route';
import { DELETE as deleteDocumentHandler } from '@/app/api/documents/[id]/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME, validateSession, createSession, hashSessionToken } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';

describe('Sessions & Escalation Path Hardening', () => {
  let adminToken: string;
  let ownerToken: string;
  let viewerToken: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    // Authenticate Admin
    const adminRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.admin.email, password: SEED_CREDENTIALS.admin.password }),
      })
    );
    adminToken = adminRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Authenticate Alice (Owner)
    const ownerRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    ownerToken = ownerRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Authenticate Carol (Viewer)
    const viewerRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    viewerToken = viewerRes.cookies.get(SESSION_COOKIE_NAME)!.value;
  });

  describe('Session Lifecycle & Invalidation', () => {
    it('rotates session on login: invalidates old session token presented in cookies', async () => {
      // 1. First login gets session A
      const login1 = await loginHandler(
        new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
        })
      );
      const tokenA = login1.cookies.get(SESSION_COOKIE_NAME)!.value;
      await expect(validateSession(tokenA)).resolves.toBeDefined();

      // 2. Second login presenting token A cookie gets session B
      const login2 = await loginHandler(
        new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
            cookie: `${SESSION_COOKIE_NAME}=${tokenA}`,
          },
          body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
        })
      );
      const tokenB = login2.cookies.get(SESSION_COOKIE_NAME)!.value;
      expect(tokenB).not.toBe(tokenA);

      // Token A must now be invalidated, Token B must be valid
      await expect(validateSession(tokenA)).rejects.toThrow();
      await expect(validateSession(tokenB)).resolves.toBeDefined();
    });

    it('sign out other devices: revokes all sessions except the current one', async () => {
      const bob = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.owner2.email) });
      const dev1 = await createSession(bob!.id, '1.1.1.1', 'Device 1');
      const dev2 = await createSession(bob!.id, '2.2.2.2', 'Device 2');

      // dev1 calls sign out other devices
      const delReq = new NextRequest('http://localhost:3000/api/auth/sessions', {
        method: 'DELETE',
        headers: { authorization: `Bearer ${dev1.rawToken}` },
      });
      const delRes = await revokeOtherSessionsHandler(delReq);
      expect(delRes.status).toBe(200);

      // dev1 remains valid, dev2 is revoked
      await expect(validateSession(dev1.rawToken)).resolves.toBeDefined();
      await expect(validateSession(dev2.rawToken)).rejects.toThrow();
    });

    it('password change immediately purges all active sessions', async () => {
      // Create user for password test
      const testEmail = 'pwd_test@trustvault.local';
      const createRes = await createUserHandler(
        new NextRequest('http://localhost:3000/api/admin/users', {
          method: 'POST',
          headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' },
          body: JSON.stringify({ email: testEmail, fullName: 'Pwd User', password: 'OldPassword123!', role: 'VIEWER' }),
        })
      );
      expect(createRes.status).toBe(201);

      // Log in to get old session
      const loginRes = await loginHandler(
        new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: JSON.stringify({ email: testEmail, password: 'OldPassword123!' }),
        })
      );
      const oldToken = loginRes.cookies.get(SESSION_COOKIE_NAME)!.value;

      // Change password
      const changeRes = await passwordChangeHandler(
        new NextRequest('http://localhost:3000/api/auth/password', {
          method: 'POST',
          headers: { authorization: `Bearer ${oldToken}`, 'content-type': 'application/json' },
          body: JSON.stringify({ currentPassword: 'OldPassword123!', newPassword: 'NewPassword999#' }),
        })
      );
      expect(changeRes.status).toBe(200);

      // Old token must fail immediately
      await expect(validateSession(oldToken)).rejects.toThrow();
    });

    it('role change immediately revokes all active sessions for that user', async () => {
      const bob = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.owner2.email) });
      const bobSession = await createSession(bob!.id, '127.0.0.1', 'Bob Browser');
      await expect(validateSession(bobSession.rawToken)).resolves.toBeDefined();

      // Admin demotes Bob from OWNER to VIEWER
      const patchReq = new NextRequest(`http://localhost:3000/api/admin/users/${bob!.id}`, {
        method: 'PATCH',
        headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'VIEWER' }),
      });
      const patchRes = await patchUserHandler(patchReq, { params: { id: bob!.id } });
      expect(patchRes.status).toBe(200);

      // Bob's session must be destroyed immediately
      await expect(validateSession(bobSession.rawToken)).rejects.toThrow();
    });

    it('rejects session when idle inactivity timeout is exceeded', async () => {
      const bob = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.owner2.email) });
      const idleSession = await createSession(bob!.id, '127.0.0.1', 'Idle Browser');

      // Artificially age last_active_at by 5 hours (idle timeout is 4 hours)
      const fiveHoursAgo = new Date(Date.now() - 5 * 60 * 60 * 1000);
      await db
        .update(schema.sessions)
        .set({ lastActiveAt: fiveHoursAgo })
        .where(eq(schema.sessions.id, idleSession.sessionId));

      await expect(validateSession(idleSession.rawToken)).rejects.toThrow('Session has expired due to inactivity');
    });
  });

  describe('Escalation Paths & Authorization Guardrails', () => {
    it('prevents non-admin from creating users or creating another admin', async () => {
      const req = new NextRequest('http://localhost:3000/api/admin/users', {
        method: 'POST',
        headers: { authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'rogue_admin@trustvault.local', fullName: 'Rogue Admin', password: 'Pass123!456', role: 'ADMIN' }),
      });
      const res = await createUserHandler(req);
      expect(res.status).toBe(403);
    });

    it('prevents self-grant: owner cannot grant permissions to themselves', async () => {
      const aliceDoc = await db.query.documents.findFirst({
        where: eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'),
      });

      const req = new NextRequest(`http://localhost:3000/api/documents/${aliceDoc!.id}/grants`, {
        method: 'POST',
        headers: { authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          targetEmail: SEED_CREDENTIALS.owner1.email, // Alice granting herself
          permission: 'READ',
        }),
      });

      const res = await createGrantHandler(req, { params: { id: aliceDoc!.id } });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toContain('already have implicit full control');
    });

    it('prevents granting permissions to nonexistent or disabled users', async () => {
      const aliceDoc = await db.query.documents.findFirst({
        where: eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'),
      });

      // Nonexistent user
      const nonExistentReq = new NextRequest(`http://localhost:3000/api/documents/${aliceDoc!.id}/grants`, {
        method: 'POST',
        headers: { authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          targetEmail: 'nobody_here@trustvault.local',
          permission: 'READ',
        }),
      });
      const nonExistentRes = await createGrantHandler(nonExistentReq, { params: { id: aliceDoc!.id } });
      expect(nonExistentRes.status).toBe(400);
      const nonExistentJson = await nonExistentRes.json();
      expect(nonExistentJson.error.message).toContain('not found in system');
    });

    it('strictly forbids an EDIT grantee from sharing or deleting the document', async () => {
      const aliceDoc = await db.query.documents.findFirst({
        where: eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'),
      });

      // Grant Bob EDIT access
      const grantReq = new NextRequest(`http://localhost:3000/api/documents/${aliceDoc!.id}/grants`, {
        method: 'POST',
        headers: { authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          targetEmail: SEED_CREDENTIALS.owner2.email,
          permission: 'EDIT',
        }),
      });
      const grantRes = await createGrantHandler(grantReq, { params: { id: aliceDoc!.id } });
      expect(grantRes.status).toBe(201);

      // Authenticate Bob
      const bobRes = await loginHandler(
        new NextRequest('http://localhost:3000/api/auth/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
        })
      );
      const bobToken = bobRes.cookies.get(SESSION_COOKIE_NAME)!.value;

      // Bob (EDIT grantee) tries to DELETE the document -> Uniform 404
      const deleteReq = new NextRequest(`http://localhost:3000/api/documents/${aliceDoc!.id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${bobToken}` },
      });
      const deleteRes = await deleteDocumentHandler(deleteReq, { params: { id: aliceDoc!.id } });
      expect(deleteRes.status).toBe(404);

      // Bob (EDIT grantee) tries to SHARE the document -> Uniform 404
      const shareReq = new NextRequest(`http://localhost:3000/api/documents/${aliceDoc!.id}/grants`, {
        method: 'POST',
        headers: { authorization: `Bearer ${bobToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({
          targetEmail: SEED_CREDENTIALS.viewer.email,
          permission: 'READ',
        }),
      });
      const shareRes = await createGrantHandler(shareReq, { params: { id: aliceDoc!.id } });
      expect(shareRes.status).toBe(404);
    });
  });
});
