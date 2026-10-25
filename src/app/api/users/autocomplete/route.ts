import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { checkActionRateLimit } from '@/server/auth/rate-limit';
import { db, schema } from '@/server/db';
import { ilike, and, eq, or } from 'drizzle-orm';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest) {
  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json(
        { error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } },
        { status: 401 }
      );
    }

    const { user } = await validateSession(token);

    // Rate Limiting Defense: 30 requests / minute
    checkActionRateLimit('autocomplete:' + user.id, 30, 60000);

    const { searchParams } = new URL(req.url);
    const q = (searchParams.get('q') || '').trim();

    // Enumeration Defense: Minimum query length of 3 characters required
    if (q.length < 3) {
      return NextResponse.json(
        { error: { code: 'QUERY_TOO_SHORT', message: 'Query must be at least 3 characters to prevent enumeration.' } },
        { status: 400 }
      );
    }

    // Query active non-disabled users, strictly returning safe public fields (id, email, fullName)
    const matchingUsers = await db
      .select({
        id: schema.users.id,
        email: schema.users.email,
        fullName: schema.users.fullName,
      })
      .from(schema.users)
      .where(
        and(
          eq(schema.users.isDisabled, false),
          or(
            ilike(schema.users.email, `%${q}%`),
            ilike(schema.users.fullName, `%${q}%`)
          )
        )
      )
      .limit(5); // Limit response size to prevent directory scraping

    return NextResponse.json({ users: matchingUsers });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json(
      { error: { code: 'INTERNAL_SERVER_ERROR', message: 'Autocomplete search failed' } },
      { status: 500 }
    );
  }
}
