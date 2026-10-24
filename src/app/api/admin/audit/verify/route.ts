import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { verifyChain } from '@/server/services/audit';
import { AppError } from '@/server/errors';

async function handleVerification(req: NextRequest) {
  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user } = await validateSession(token);

    if (user.role !== 'ADMIN') {
      return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Admin access required to verify audit chain.' } }, { status: 403 });
    }

    const result = await verifyChain();

    const badge = result.valid
      ? 'CHAIN VERIFIED'
      : `TAMPERING DETECTED at #${result.brokenAtSequence}`;

    return NextResponse.json({
      badge,
      ...result,
      verifiedAt: new Date().toISOString(),
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Verification routine failed' } }, { status: 500 });
  }
}

export async function GET(req: NextRequest) {
  return handleVerification(req);
}

export async function POST(req: NextRequest) {
  return handleVerification(req);
}
