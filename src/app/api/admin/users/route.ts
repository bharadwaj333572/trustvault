import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq, desc } from 'drizzle-orm';
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

    if (user.role !== 'ADMIN') {
      return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Admin access required to create users.' } }, { status: 403 });
    }

    const body = await req.json();
    const { email, fullName, password, role } = body;

    if (!email || !fullName || !password) {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'email, fullName, and password are required' } },
        { status: 400 }
      );
    }

    const validRoles = ['ADMIN', 'OWNER', 'VIEWER'];
    const assignedRole = validRoles.includes(role) ? role : 'VIEWER';

    const normalizedEmail = email.toLowerCase().trim();

    // Check if user already exists
    const existing = await db
      .select({ id: schema.users.id })
      .from(schema.users)
      .where(eq(schema.users.email, normalizedEmail))
      .limit(1);

    if (existing.length > 0) {
      return NextResponse.json(
        { error: { code: 'USER_EXISTS', message: `User with email "${normalizedEmail}" already exists.` } },
        { status: 400 }
      );
    }

    const { hashPassword } = await import('@/server/auth/password');
    const passwordHash = await hashPassword(password);
    const newUserId = crypto.randomUUID();
    const now = new Date();

    const [newUser] = await db
      .insert(schema.users)
      .values({
        id: newUserId,
        email: normalizedEmail,
        fullName: fullName.trim(),
        passwordHash,
        role: assignedRole,
        isDisabled: false,
        createdAt: now,
        updatedAt: now,
      })
      .returning();

    const { logAuditEvent } = await import('@/server/services/audit');
    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      action: 'USER_CREATE',
      outcome: 'ALLOWED',
      details: {
        createdUserId: newUser.id,
        createdUserEmail: newUser.email,
        assignedRole: newUser.role,
      },
    });

    return NextResponse.json(
      {
        user: {
          id: newUser.id,
          email: newUser.email,
          fullName: newUser.fullName,
          role: newUser.role,
          isDisabled: newUser.isDisabled,
          createdAt: newUser.createdAt,
        },
      },
      { status: 201 }
    );
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to create user' } }, { status: 500 });
  }
}
