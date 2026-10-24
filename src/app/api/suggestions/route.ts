import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getSharingSuggestions } from '@/server/services/suggestions';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest) {
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
    const { searchParams } = new URL(req.url);
    const documentId = searchParams.get('documentId');

    if (!documentId) {
      return NextResponse.json({ error: { code: 'VALIDATION_ERROR', message: 'documentId parameter is required' } }, { status: 400 });
    }

    const suggestions = await getSharingSuggestions(user, documentId, ip, userAgent);

    return NextResponse.json({
      suggestions,
      disclaimer: 'AI suggestions are advisory only and grant ZERO access automatically. A person must confirm each grant.',
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to generate suggestions' } }, { status: 500 });
  }
}
