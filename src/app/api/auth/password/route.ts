import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { eq } from 'drizzle-orm';
import { db, schema } from '@/server/db';
import { validateSession, SESSION_COOKIE_NAME, revokeAllUserSessions, createSession, SESSION_TTL_SECONDS } from '@/server/auth/session';
import { verifyPassword, hashPassword } from '@/server/auth/password';
import { logAuditEvent } from '@/server/services/audit';
import { AppError } from '@/server/errors';

const PasswordChangeSchema = z.object({
  currentPassword: z.string().min(1).max(128),
  newPassword: z.string().min(10).max(128),
});

/**
 * Authenticated password change.
 * Deletes ALL sessions for the user (including current), then issues a fresh rotated session.
 */
export async function POST(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } },
        { status: 401 }
      );
    }

    const { user } = await validateSession(token);
    const body = await req.json().catch(() => ({}));
    const parsed = PasswordChangeSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'currentPassword and newPassword (min 10 chars) are required' } },
        { status: 400 }
      );
    }

    const { currentPassword, newPassword } = parsed.data;

    const rows = await db.select().from(schema.users).where(eq(schema.users.id, user.id)).limit(1);
    if (rows.length === 0) {
      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } },
        { status: 401 }
      );
    }

    const dbUser = rows[0];
    const valid = await verifyPassword(dbUser.passwordHash, currentPassword);
    if (!valid) {
      await logAuditEvent({
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        ipAddress: ip,
        userAgent,
        action: 'PASSWORD_CHANGE',
        outcome: 'DENIED',
        reason: 'INVALID_CURRENT_PASSWORD',
      });
      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'Current password is incorrect' } },
        { status: 401 }
      );
    }

    const passwordHash = await hashPassword(newPassword);
    await db
      .update(schema.users)
      .set({ passwordHash, updatedAt: new Date() })
      .where(eq(schema.users.id, user.id));

    // Delete ALL sessions after password change
    await revokeAllUserSessions(user.id);

    const { rawToken, expiresAt } = await createSession(user.id, ip, userAgent);

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      action: 'PASSWORD_CHANGE',
      outcome: 'ALLOWED',
      reason: 'PASSWORD_ROTATED_SESSIONS_REVOKED',
    });

    const isSecure = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';
    const response = NextResponse.json({
      success: true,
      message: 'Password updated. All other sessions have been revoked.',
    });

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
    return NextResponse.json(
      { error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to change password' } },
      { status: 500 }
    );
  }
}
