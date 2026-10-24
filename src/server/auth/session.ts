import crypto from 'crypto';
import { db, schema } from '../db';
import { eq, and, gt } from 'drizzle-orm';
import { UnauthenticatedError } from '../errors';
import { cookies } from 'next/headers';

export const SESSION_COOKIE_NAME = 'trustvault_session';
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7; // 7 days

export interface AuthenticatedUser {
  id: string;
  email: string;
  fullName: string;
  role: 'ADMIN' | 'OWNER' | 'VIEWER';
  isDisabled: boolean;
}

export interface SessionData {
  sessionId: string;
  userId: string;
  expiresAt: Date;
  user: AuthenticatedUser;
}

/**
 * Hash raw session token using SHA-256 for safe DB storage.
 */
export function hashSessionToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Creates a new DB-backed session with an opaque 256-bit token.
 */
export async function createSession(
  userId: string,
  ipAddress?: string | null,
  userAgent?: string | null
): Promise<{ rawToken: string; expiresAt: Date; sessionId: string }> {
  const rawToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = hashSessionToken(rawToken);
  const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);

  await db.insert(schema.sessions).values({
    id: tokenHash,
    userId,
    expiresAt,
    ipAddress: ipAddress || null,
    userAgent: userAgent || null,
    createdAt: new Date(),
  });

  return { rawToken, expiresAt, sessionId: tokenHash };
}

/**
 * Validates a session from a raw token.
 * IMMEDIATELY revokes and rejects if the user account has been disabled.
 */
export async function validateSession(rawToken: string): Promise<SessionData> {
  if (!rawToken || typeof rawToken !== 'string') {
    throw new UnauthenticatedError('Missing session token');
  }

  const tokenHash = hashSessionToken(rawToken);
  const now = new Date();

  // Query active session and join user
  const result = await db
    .select({
      sessionId: schema.sessions.id,
      userId: schema.sessions.userId,
      expiresAt: schema.sessions.expiresAt,
      id: schema.users.id,
      email: schema.users.email,
      fullName: schema.users.fullName,
      role: schema.users.role,
      isDisabled: schema.users.isDisabled,
    })
    .from(schema.sessions)
    .innerJoin(schema.users, eq(schema.sessions.userId, schema.users.id))
    .where(and(eq(schema.sessions.id, tokenHash), gt(schema.sessions.expiresAt, now)))
    .limit(1);

  if (result.length === 0) {
    throw new UnauthenticatedError('Session is invalid or expired');
  }

  const row = result[0];

  // Immediate Revocation Rule: If user is disabled, destroy session immediately!
  if (row.isDisabled) {
    await db.delete(schema.sessions).where(eq(schema.sessions.userId, row.userId));
    throw new UnauthenticatedError('Account has been disabled by an administrator');
  }

  return {
    sessionId: row.sessionId,
    userId: row.userId,
    expiresAt: row.expiresAt,
    user: {
      id: row.id,
      email: row.email,
      fullName: row.fullName,
      role: row.role as 'ADMIN' | 'OWNER' | 'VIEWER',
      isDisabled: row.isDisabled,
    },
  };
}

/**
 * Revokes a single session.
 */
export async function revokeSession(rawToken: string): Promise<void> {
  const tokenHash = hashSessionToken(rawToken);
  await db.delete(schema.sessions).where(eq(schema.sessions.id, tokenHash));
}

/**
 * Revokes ALL active sessions for a user (used for disabling or password reset).
 */
export async function revokeAllUserSessions(userId: string): Promise<void> {
  await db.delete(schema.sessions).where(eq(schema.sessions.userId, userId));
}

/**
 * Cookie helpers for Next.js Server Components and Route Handlers
 */
export function getSessionCookie(): string | undefined {
  try {
    const cookieStore = cookies();
    return cookieStore.get(SESSION_COOKIE_NAME)?.value;
  } catch {
    return undefined;
  }
}
