import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { verifyPassword } from '@/server/auth/password';
import { createSession, SESSION_COOKIE_NAME, SESSION_TTL_SECONDS } from '@/server/auth/session';
import { checkIpRateLimit, checkAccountLockout, recordFailedLogin, resetFailedLogin } from '@/server/auth/rate-limit';
import { logAuditEvent } from '@/server/services/audit';
import { AppError } from '@/server/errors';

const LoginSchema = z.object({
  email: z.string().email().max(255),
  password: z.string().min(1).max(128),
});

export async function POST(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    // 1. Check IP rate limit
    checkIpRateLimit(ip);

    const body = await req.json();
    const parsed = LoginSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'Invalid email or password format' } },
        { status: 400 }
      );
    }

    const { email, password } = parsed.data;
    const normalizedEmail = email.toLowerCase().trim();

    // 2. Check Account Lockout status
    await checkAccountLockout(normalizedEmail);

    // 3. Find user
    const users = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, normalizedEmail))
      .limit(1);

    if (users.length === 0) {
      // Record failed attempt and log audit failure
      await logAuditEvent({
        actorEmail: normalizedEmail,
        ipAddress: ip,
        userAgent,
        action: 'LOGIN_FAILURE',
        outcome: 'DENIED',
        reason: 'INVALID_CREDENTIALS',
      });

      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'Invalid email or password' } },
        { status: 401 }
      );
    }

    const user = users[0];

    // Check if account is disabled
    if (user.isDisabled) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        ipAddress: ip,
        userAgent,
        action: 'LOGIN_FAILURE',
        outcome: 'DENIED',
        reason: 'ACCOUNT_DISABLED',
      });

      return NextResponse.json(
        { error: { code: 'UNAUTHORIZED', message: 'Account is disabled. Contact system administrator.' } },
        { status: 403 }
      );
    }

    // 4. Verify password with Argon2id
    const isValid = await verifyPassword(user.passwordHash, password);

    if (!isValid) {
      const wasLocked = await recordFailedLogin(normalizedEmail);

      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        ipAddress: ip,
        userAgent,
        action: 'LOGIN_FAILURE',
        outcome: 'DENIED',
        reason: wasLocked ? 'ACCOUNT_LOCKOUT_TRIGGERED' : 'INVALID_CREDENTIALS',
      });

      if (wasLocked) {
        return NextResponse.json(
          { error: { code: 'LOCKED_OUT', message: 'Account has been locked due to excessive failed attempts. Please retry in 15 minutes.' } },
          { status: 423 }
        );
      }

      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'Invalid email or password' } },
        { status: 401 }
      );
    }

    // 5. Successful login: reset failed login counter
    await resetFailedLogin(user.id);

    // 6. Create DB session
    const { rawToken, expiresAt } = await createSession(user.id, ip, userAgent);

    // 7. Record login success in audit hash chain
    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      action: 'LOGIN_SUCCESS',
      outcome: 'ALLOWED',
      reason: 'PASSWORD_AUTHENTICATED',
    });

    const isSecure = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';

    const response = NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
      },
    });

    // Set HttpOnly, SameSite=Lax session cookie
    response.cookies.set({
      name: SESSION_COOKIE_NAME,
      value: rawToken,
      httpOnly: true,
      secure: isSecure,
      sameSite: 'lax',
      path: '/',
      expires: expiresAt,
      maxAge: SESSION_TTL_SECONDS,
    });

    return response;
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    console.error('Unhandled login error:', err);
    return NextResponse.json(
      { error: { code: 'INTERNAL_SERVER_ERROR', message: 'An unexpected authentication error occurred.' } },
      { status: 500 }
    );
  }
}
