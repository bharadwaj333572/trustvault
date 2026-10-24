import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest) {
  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const headerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : undefined;
    const token = cookieToken || headerToken;

    if (!token) {
      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'No active session token provided' } },
        { status: 401 }
      );
    }

    const sessionData = await validateSession(token);

    return NextResponse.json({
      user: sessionData.user,
      expiresAt: sessionData.expiresAt,
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json(
      { error: { code: 'UNAUTHENTICATED', message: 'Invalid or expired session' } },
      { status: 401 }
    );
  }
}
