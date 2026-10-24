import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { desc } from 'drizzle-orm';
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
      return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Admin access required to view users directory.' } }, { status: 403 });
    }

    const userList = await db
      .select({
        id: schema.users.id,
        email: schema.users.email,
        fullName: schema.users.fullName,
        role: schema.users.role,
        isDisabled: schema.users.isDisabled,
        failedLoginAttempts: schema.users.failedLoginAttempts,
        lockedUntil: schema.users.lockedUntil,
        createdAt: schema.users.createdAt,
        updatedAt: schema.users.updatedAt,
      })
      .from(schema.users)
      .orderBy(desc(schema.users.createdAt));

    return NextResponse.json({ users: userList });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to retrieve users' } }, { status: 500 });
  }
}
