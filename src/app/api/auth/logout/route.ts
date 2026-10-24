import { NextRequest, NextResponse } from 'next/server';
import { revokeSession, SESSION_COOKIE_NAME, validateSession } from '@/server/auth/session';
import { logAuditEvent } from '@/server/services/audit';

export async function POST(req: NextRequest) {
  const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
  const authHeader = req.headers.get('authorization');
  const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : undefined);
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  if (token) {
    try {
      const sessionData = await validateSession(token);
      await logAuditEvent({
        actorId: sessionData.user.id,
        actorEmail: sessionData.user.email,
        actorRole: sessionData.user.role,
        ipAddress: ip,
        userAgent,
        action: 'LOGOUT',
        outcome: 'ALLOWED',
        reason: 'USER_LOGOUT',
      });
    } catch {
      // Session might already be invalid
    }
    await revokeSession(token);
  }

  const response = NextResponse.json({ success: true, message: 'Logged out successfully' });
  response.cookies.delete(SESSION_COOKIE_NAME);
  return response;
}
