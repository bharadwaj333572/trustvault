import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME, hashSessionToken } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq, and, ne, desc } from 'drizzle-orm';
import { logAuditEvent } from '@/server/services/audit';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest) {
  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user, sessionId } = await validateSession(token);
    const activeSessions = await db
      .select({
        id: schema.sessions.id,
        ipAddress: schema.sessions.ipAddress,
        userAgent: schema.sessions.userAgent,
        createdAt: schema.sessions.createdAt,
        expiresAt: schema.sessions.expiresAt,
      })
      .from(schema.sessions)
      .where(eq(schema.sessions.userId, user.id))
      .orderBy(desc(schema.sessions.createdAt));

    const formattedSessions = activeSessions.map((s) => ({
      id: s.id,
      ipAddress: s.ipAddress || 'Unknown IP',
      userAgent: s.userAgent || 'Unknown Browser',
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      isCurrent: s.id === sessionId,
    }));

    return NextResponse.json({ sessions: formattedSessions });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to retrieve sessions' } }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user, sessionId } = await validateSession(token);

    // Revoke all sessions for this user EXCEPT the current session
    await db
      .delete(schema.sessions)
      .where(
        and(
          eq(schema.sessions.userId, user.id),
          ne(schema.sessions.id, sessionId)
        )
      );

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      action: 'SESSIONS_REVOKED_OTHERS',
      outcome: 'ALLOWED',
      details: {
        preservedSessionId: sessionId,
      },
    });

    return NextResponse.json({
      success: true,
      message: 'Successfully signed out of all other devices.',
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to revoke other sessions' } }, { status: 500 });
  }
}
