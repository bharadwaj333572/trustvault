import { NextRequest } from 'next/server';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { SEED_CREDENTIALS } from '../../scripts/seed';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { createSession, revokeAllUserSessions } from '@/server/auth/session';

export type ActorName = 'ownerA' | 'ownerB' | 'viewer' | 'admin' | 'anonymous' | 'disabled';

export function originHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    origin: 'http://localhost:3000',
    host: 'localhost:3000',
    ...extra,
  };
}

export async function loginAs(
  email: string,
  password: string
): Promise<string> {
  const res = await loginHandler(
    new NextRequest('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...originHeaders() },
      body: JSON.stringify({ email, password }),
    })
  );
  const token = res.cookies.get(SESSION_COOKIE_NAME)?.value;
  if (!token) {
    throw new Error(`Login failed for ${email}: status=${res.status}`);
  }
  return token;
}

export async function loginSeedActors(): Promise<Record<'admin' | 'ownerA' | 'ownerB' | 'viewer', string>> {
  const [admin, ownerA, ownerB, viewer] = await Promise.all([
    loginAs(SEED_CREDENTIALS.admin.email, SEED_CREDENTIALS.admin.password),
    loginAs(SEED_CREDENTIALS.owner1.email, SEED_CREDENTIALS.owner1.password),
    loginAs(SEED_CREDENTIALS.owner2.email, SEED_CREDENTIALS.owner2.password),
    loginAs(SEED_CREDENTIALS.viewer.email, SEED_CREDENTIALS.viewer.password),
  ]);
  return { admin, ownerA, ownerB, viewer };
}

/** Mint fresh sessions without hitting the login IP rate limiter. */
export async function mintSeedActorTokens(): Promise<
  Record<'admin' | 'ownerA' | 'ownerB' | 'viewer', string>
> {
  const mapping: Array<['admin' | 'ownerA' | 'ownerB' | 'viewer', string]> = [
    ['admin', SEED_CREDENTIALS.admin.email],
    ['ownerA', SEED_CREDENTIALS.owner1.email],
    ['ownerB', SEED_CREDENTIALS.owner2.email],
    ['viewer', SEED_CREDENTIALS.viewer.email],
  ];
  const out = {} as Record<'admin' | 'ownerA' | 'ownerB' | 'viewer', string>;
  for (const [key, email] of mapping) {
    const { token } = await mintSessionForEmail(email);
    out[key] = token;
  }
  return out;
}

/**
 * Create a disabled-user session token by logging in then flipping isDisabled
 * without purging that specific token (simulates stale cookie after disable race),
 * OR by creating a session then disabling + NOT revoking — we revoke then create
 * a session while disabled is false, then disable without purge for testing validateSession.
 *
 * For inventory probes we need validateSession to reject: disable + revokeAll.
 * Disabled actor therefore presents a token that was valid before disable (revoked).
 */
export async function createDisabledActorToken(): Promise<string> {
  const token = await loginAs(SEED_CREDENTIALS.viewer.email, SEED_CREDENTIALS.viewer.password);
  const users = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, SEED_CREDENTIALS.viewer.email))
    .limit(1);
  const userId = users[0]!.id;
  await db.update(schema.users).set({ isDisabled: true, updatedAt: new Date() }).where(eq(schema.users.id, userId));
  await revokeAllUserSessions(userId);
  // Re-enable for other tests that need Carol; token remains invalid because sessions purged.
  // Keep disabled flag true for login-as-disabled probes; restore after suite if needed.
  return token;
}

export async function ensureViewerEnabled(): Promise<void> {
  await db
    .update(schema.users)
    .set({ isDisabled: false, updatedAt: new Date() })
    .where(eq(schema.users.email, SEED_CREDENTIALS.viewer.email));
}

export function authHeader(token: string | null | undefined): Record<string, string> {
  if (!token) return {};
  return { authorization: `Bearer ${token}` };
}

/** Create a session for a user without going through login (for timeout tests). */
export async function mintSessionForEmail(email: string): Promise<{ token: string; userId: string }> {
  const users = await db.select().from(schema.users).where(eq(schema.users.email, email)).limit(1);
  if (users.length === 0) throw new Error(`No user ${email}`);
  const { rawToken } = await createSession(users[0]!.id, '127.0.0.1', 'test-agent');
  return { token: rawToken, userId: users[0]!.id };
}
