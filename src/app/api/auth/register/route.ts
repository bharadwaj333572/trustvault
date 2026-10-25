import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import crypto from 'crypto';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { hashPassword } from '@/server/auth/password';
import { createSession, revokeSession, SESSION_COOKIE_NAME, SESSION_TTL_SECONDS } from '@/server/auth/session';
import { checkIpRateLimit } from '@/server/auth/rate-limit';
import { logAuditEvent } from '@/server/services/audit';
import { AppError } from '@/server/errors';

const RegisterSchema = z.object({
  fullName: z.string().trim().min(1, 'Full name is required').max(100),
  email: z.string().email('Invalid email address format').max(255),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128),
});

export async function POST(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    // 1. IP-level rate limiting
    checkIpRateLimit(ip);

    let body: any;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'Malformed JSON payload' } },
        { status: 400 }
      );
    }

    const parsed = RegisterSchema.safeParse(body);
    if (!parsed.success) {
      return NextResponse.json(
        {
          error: {
            code: 'VALIDATION_ERROR',
            message: parsed.error.issues[0]?.message || 'Invalid registration data',
          },
        },
        { status: 400 }
      );
    }

    const { fullName, email, password } = parsed.data;
    const normalizedEmail = email.toLowerCase().trim();

    // 2. Check if user already exists
    const existing = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, normalizedEmail))
      .limit(1);

    if (existing.length > 0) {
      return NextResponse.json(
        {
          error: {
            code: 'USER_EXISTS',
            message: 'An account with this email already exists. Please sign in instead.',
          },
        },
        { status: 409 }
      );
    }

    // 3. Hash password using Argon2id (OWASP recommended parameters)
    const passwordHash = await hashPassword(password);
    const newUserId = crypto.randomUUID();

    // 4. Create new user with OWNER role
    // Defaulting to OWNER gives user their personal "My Documents" dashboard, file upload, and sharing
    await db.insert(schema.users).values({
      id: newUserId,
      email: normalizedEmail,
      fullName: fullName.trim(),
      passwordHash,
      role: schema.UserRole.OWNER,
      isDisabled: false,
    });

    // 5. Rotate session: revoke any existing session token on the incoming cookie
    const existingCookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    if (existingCookieToken) {
      await revokeSession(existingCookieToken).catch(() => {});
    }

    // 6. Create authenticated DB session
    const { rawToken, expiresAt } = await createSession(newUserId, ip, userAgent);

    // 7. Append-only tamper-evident audit record
    await logAuditEvent({
      actorId: newUserId,
      actorEmail: normalizedEmail,
      actorRole: schema.UserRole.OWNER,
      ipAddress: ip,
      userAgent,
      action: 'LOGIN_SUCCESS',
      outcome: 'ALLOWED',
      reason: 'ACCOUNT_REGISTERED_AND_AUTHENTICATED',
      details: {
        registration: true,
        role: schema.UserRole.OWNER,
      },
    });

    const isSecure = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';

    const response = NextResponse.json(
      {
        success: true,
        message: 'Account successfully registered and authenticated.',
        user: {
          id: newUserId,
          email: normalizedEmail,
          fullName: fullName.trim(),
          role: schema.UserRole.OWNER,
        },
      },
      { status: 201 }
    );

    // 8. Set HttpOnly, SameSite=Lax session cookie
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
    console.error('Unhandled registration error:', err);
    return NextResponse.json(
      { error: { code: 'INTERNAL_SERVER_ERROR', message: 'An unexpected registration error occurred.' } },
      { status: 500 }
    );
  }
}
