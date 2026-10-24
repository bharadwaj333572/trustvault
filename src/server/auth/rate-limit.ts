import { db, schema } from '../db';
import { eq } from 'drizzle-orm';
import { AccountLockedOutError, RateLimitedError } from '../errors';

interface IpRateRecord {
  attempts: number;
  resetAt: number;
}

const MAX_IP_ATTEMPTS = 15;
const IP_WINDOW_MS = 60 * 1000; // 1 minute
const ipStore = new Map<string, IpRateRecord>();

const MAX_ACCOUNT_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

/**
 * Checks IP-level rate limiting.
 */
export function checkIpRateLimit(ip: string): void {
  const now = Date.now();
  const record = ipStore.get(ip);

  if (!record || now > record.resetAt) {
    ipStore.set(ip, { attempts: 1, resetAt: now + IP_WINDOW_MS });
    return;
  }

  if (record.attempts >= MAX_IP_ATTEMPTS) {
    const secondsRemaining = Math.ceil((record.resetAt - now) / 1000);
    throw new RateLimitedError(secondsRemaining);
  }

  record.attempts += 1;
}

/**
 * Checks whether an account is currently locked out due to previous failed attempts.
 */
export async function checkAccountLockout(email: string): Promise<void> {
  const users = await db
    .select({
      id: schema.users.id,
      failedAttempts: schema.users.failedLoginAttempts,
      lockedUntil: schema.users.lockedUntil,
    })
    .from(schema.users)
    .where(eq(schema.users.email, email.toLowerCase().trim()))
    .limit(1);

  if (users.length === 0) {
    return; // Do not reveal whether user exists
  }

  const user = users[0];
  const now = new Date();

  if (user.lockedUntil && user.lockedUntil > now) {
    const minutesRemaining = Math.ceil((user.lockedUntil.getTime() - now.getTime()) / (60 * 1000));
    throw new AccountLockedOutError(minutesRemaining);
  }
}

/**
 * Records a failed login attempt for an account. Triggers lockout after 5 consecutive failures.
 */
export async function recordFailedLogin(email: string): Promise<boolean> {
  const normalizedEmail = email.toLowerCase().trim();
  const users = await db
    .select({
      id: schema.users.id,
      failedAttempts: schema.users.failedLoginAttempts,
    })
    .from(schema.users)
    .where(eq(schema.users.email, normalizedEmail))
    .limit(1);

  if (users.length === 0) {
    return false;
  }

  const user = users[0];
  const newFailedAttempts = user.failedAttempts + 1;
  const now = new Date();

  if (newFailedAttempts >= MAX_ACCOUNT_FAILED_ATTEMPTS) {
    const lockedUntil = new Date(now.getTime() + LOCKOUT_DURATION_MINUTES * 60 * 1000);
    await db
      .update(schema.users)
      .set({
        failedLoginAttempts: newFailedAttempts,
        lockedUntil,
        updatedAt: now,
      })
      .where(eq(schema.users.id, user.id));
    return true; // Was locked
  } else {
    await db
      .update(schema.users)
      .set({
        failedLoginAttempts: newFailedAttempts,
        updatedAt: now,
      })
      .where(eq(schema.users.id, user.id));
    return false;
  }
}

/**
 * Resets the failed login counter after a successful login.
 */
export async function resetFailedLogin(userId: string): Promise<void> {
  await db
    .update(schema.users)
    .set({
      failedLoginAttempts: 0,
      lockedUntil: null,
      updatedAt: new Date(),
    })
    .where(eq(schema.users.id, userId));
}
