import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { recordSuggestionFeedback } from '@/server/services/suggestions';
import { AppError } from '@/server/errors';

export async function POST(req: NextRequest) {
  const ip = req.headers.get('x-forwarded-for') || '127.0.0.1';
  const userAgent = req.headers.get('user-agent') || 'unknown';

  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user } = await validateSession(token);
    const body = await req.json();

    if (!body.documentId || !body.targetEmail || typeof body.accepted !== 'boolean') {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'documentId, targetEmail, and accepted (boolean) are required' } },
        { status: 400 }
      );
    }

    await recordSuggestionFeedback(user, body.documentId, body.targetEmail, body.accepted, ip, userAgent);

    return NextResponse.json({ success: true });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to record feedback' } }, { status: 500 });
  }
}
