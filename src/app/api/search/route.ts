import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq, and, sql, desc, or, ilike, gte, lte } from 'drizzle-orm';
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
    const { searchParams } = new URL(req.url);

    const q = searchParams.get('q') || '';
    const category = searchParams.get('category') || undefined;
    const ownerEmail = searchParams.get('owner') || undefined;
    const startDate = searchParams.get('startDate') ? new Date(searchParams.get('startDate')!) : undefined;
    const endDate = searchParams.get('endDate') ? new Date(searchParams.get('endDate')!) : undefined;
    const limit = Math.min(searchParams.get('limit') ? parseInt(searchParams.get('limit')!, 10) : 20, 50);
    const page = Math.max(searchParams.get('page') ? parseInt(searchParams.get('page')!, 10) : 1, 1);
    const offset = (page - 1) * limit;

    const now = new Date();

    // STRICT SQL-LEVEL AUTHORIZATION:
    // User must be the Owner OR have an active, unexpired grant in document_grants.
    // Untrusted documents are never returned or counted.
    const authCondition = or(
      eq(schema.documents.ownerId, user.id),
      sql`${schema.documents.id} IN (
        SELECT ${schema.documentGrants.documentId} 
        FROM ${schema.documentGrants} 
        WHERE ${schema.documentGrants.userId} = ${user.id} 
        AND (${schema.documentGrants.expiresAt} IS NULL OR ${schema.documentGrants.expiresAt} > ${now})
      )`
    );

    const conditions = [
      authCondition,
      eq(schema.documents.isDeleted, false), // Exclude soft-deleted
    ];

    if (q.trim()) {
      conditions.push(ilike(schema.documents.title, `%${q.trim()}%`));
    }

    if (category) {
      conditions.push(eq(schema.documents.category, category));
    }

    if (ownerEmail) {
      conditions.push(ilike(schema.users.email, `%${ownerEmail.trim()}%`));
    }

    if (startDate) {
      conditions.push(gte(schema.documents.createdAt, startDate));
    }

    if (endDate) {
      conditions.push(lte(schema.documents.createdAt, endDate));
    }

    const [countResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(schema.documents)
      .innerJoin(schema.users, eq(schema.documents.ownerId, schema.users.id))
      .where(and(...conditions));

    const total = Number(countResult?.count || 0);

    const items = await db
      .select({
        id: schema.documents.id,
        title: schema.documents.title,
        originalFileName: schema.documents.originalFileName,
        mimeType: schema.documents.mimeType,
        fileSize: schema.documents.fileSize,
        category: schema.documents.category,
        folderPath: schema.documents.folderPath,
        ownerId: schema.documents.ownerId,
        ownerName: schema.users.fullName,
        ownerEmail: schema.users.email,
        currentVersion: schema.documents.currentVersion,
        createdAt: schema.documents.createdAt,
        updatedAt: schema.documents.updatedAt,
      })
      .from(schema.documents)
      .innerJoin(schema.users, eq(schema.documents.ownerId, schema.users.id))
      .where(and(...conditions))
      .orderBy(desc(schema.documents.updatedAt))
      .limit(limit)
      .offset(offset);

    return NextResponse.json({
      items,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Search execution failed' } }, { status: 500 });
  }
}
