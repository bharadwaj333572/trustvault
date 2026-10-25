import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { listDocumentGrants, createDocumentGrant } from '@/server/services/grants';
import { checkActionRateLimit } from '@/server/auth/rate-limit';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user } = await validateSession(token);
    const grants = await listDocumentGrants(user, params.id);

    return NextResponse.json({ grants });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to list grants' } }, { status: 500 });
  }
}

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
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
    checkActionRateLimit('share:' + user.id, 30, 60000);
    const body = await req.json();

    if (!body.targetEmail || !body.permission) {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'targetEmail and permission (READ | EDIT) are required' } },
        { status: 400 }
      );
    }

    const grant = await createDocumentGrant(
      user,
      params.id,
      {
        targetEmail: body.targetEmail,
        permission: body.permission,
        expiresAt: body.expiresAt || null,
      },
      ip,
      userAgent
    );

    return NextResponse.json({ success: true, grant }, { status: 201 });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: err.message || 'Failed to create grant' } }, { status: 500 });
  }
}
