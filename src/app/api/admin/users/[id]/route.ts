import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME, revokeAllUserSessions } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { logAuditEvent } from '@/server/services/audit';
import { AppError, ValidationError } from '@/server/errors';

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user: adminUser } = await validateSession(token);

    if (adminUser.role !== 'ADMIN') {
      return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Admin access required to modify user accounts.' } }, { status: 403 });
    }

    const targetUserRows = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.id, params.id))
      .limit(1);

    if (targetUserRows.length === 0) {
      return NextResponse.json({ error: { code: 'NOT_FOUND', message: 'User not found' } }, { status: 404 });
    }

    const targetUser = targetUserRows[0];
    const body = await req.json();
    const now = new Date();
    const updatePayload: Record<string, any> = { updatedAt: now };

    // 1. Role Change
    if (body.role && ['ADMIN', 'OWNER', 'VIEWER'].includes(body.role)) {
      if (body.role !== targetUser.role) {
        updatePayload.role = body.role;

        // Immediate Invalidation: Purge all active sessions when user role changes to prevent privilege confusion
        await revokeAllUserSessions(targetUser.id);

        await logAuditEvent({
          actorId: adminUser.id,
          actorEmail: adminUser.email,
          actorRole: adminUser.role,
          ipAddress: ip,
          userAgent,
          action: 'ROLE_CHANGE',
          outcome: 'ALLOWED',
          reason: 'ADMIN_MODIFIED_USER_ROLE',
          details: {
            targetUserId: targetUser.id,
            targetEmail: targetUser.email,
            previousRole: targetUser.role,
            newRole: body.role,
            sessionsRevoked: true,
          },
        });
      }
    }

    // 2. Disablement / Enablement
    if (typeof body.isDisabled === 'boolean') {
      updatePayload.isDisabled = body.isDisabled;

      if (body.isDisabled) {
        // Immediate Revocation: Purge all active sessions for the disabled user!
        await revokeAllUserSessions(targetUser.id);

        await logAuditEvent({
          actorId: adminUser.id,
          actorEmail: adminUser.email,
          actorRole: adminUser.role,
          ipAddress: ip,
          userAgent,
          action: 'USER_DISABLE',
          outcome: 'ALLOWED',
          reason: 'ADMIN_DISABLED_ACCOUNT',
          details: {
            targetUserId: targetUser.id,
            targetEmail: targetUser.email,
            sessionsPurged: true,
          },
        });
      }
    }

    await db
      .update(schema.users)
      .set(updatePayload)
      .where(eq(schema.users.id, targetUser.id));

    return NextResponse.json({
      success: true,
      message: 'User account updated successfully',
      updatedFields: Object.keys(updatePayload),
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to update user account' } }, { status: 500 });
  }
}
