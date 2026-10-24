import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getSecurityAlerts } from '@/server/services/alerts';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest) {
  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user } = await validateSession(token);

    if (user.role !== 'ADMIN') {
      return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Admin access required to view alerts.' } }, { status: 403 });
    }

    const alerts = await getSecurityAlerts();

    return NextResponse.json({
      alerts,
      count: alerts.length,
      evaluatedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to evaluate security alerts' } }, { status: 500 });
  }
}
