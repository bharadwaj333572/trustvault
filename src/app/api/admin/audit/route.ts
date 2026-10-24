import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { desc, and, eq, ilike, sql } from 'drizzle-orm';
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

    // Only ADMIN role may inspect the global audit trail
    if (user.role !== 'ADMIN') {
      return NextResponse.json({ error: { code: 'UNAUTHORIZED', message: 'Admin access required to view global audit log.' } }, { status: 403 });
    }

    const { searchParams } = new URL(req.url);
    const format = searchParams.get('format');
    const action = searchParams.get('action') || undefined;
    const outcome = searchParams.get('outcome') || undefined;
    const actorEmail = searchParams.get('actor') || undefined;
    const limit = Math.min(searchParams.get('limit') ? parseInt(searchParams.get('limit')!, 10) : 50, 500);
    const page = Math.max(searchParams.get('page') ? parseInt(searchParams.get('page')!, 10) : 1, 1);
    const offset = (page - 1) * limit;

    const conditions = [];

    if (action) {
      conditions.push(eq(schema.auditLogs.action, action));
    }
    if (outcome) {
      conditions.push(eq(schema.auditLogs.outcome, outcome));
    }
    if (actorEmail) {
      conditions.push(ilike(schema.auditLogs.actorEmail, `%${actorEmail.trim()}%`));
    }

    const whereClause = conditions.length > 0 ? and(...conditions) : undefined;

    // 1. Handle CSV Export
    if (format === 'csv') {
      const logs = await db
        .select()
        .from(schema.auditLogs)
        .where(whereClause)
        .orderBy(desc(schema.auditLogs.sequenceNumber))
        .limit(1000);

      const headers = ['sequence_number', 'timestamp', 'action', 'outcome', 'actor_email', 'actor_role', 'ip_address', 'document_id', 'reason', 'prev_hash', 'row_hash'];
      const csvLines = [headers.join(',')];

      for (const row of logs) {
        const line = [
          row.sequenceNumber,
          `"${row.createdAt.toISOString()}"`,
          `"${row.action}"`,
          `"${row.outcome}"`,
          `"${row.actorEmail || ''}"`,
          `"${row.actorRole || ''}"`,
          `"${row.ipAddress || ''}"`,
          `"${row.documentId || ''}"`,
          `"${(row.reason || '').replace(/"/g, '""')}"`,
          `"${row.prevHash}"`,
          `"${row.rowHash}"`,
        ];
        csvLines.push(line.join(','));
      }

      return new NextResponse(csvLines.join('\n'), {
        status: 200,
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="trustvault_audit_export_${Date.now()}.csv"`,
        },
      });
    }

    // 2. Standard JSON Response with Pagination
    const [countRow] = await db
      .select({ count: sql<number>`count(*)` })
      .from(schema.auditLogs)
      .where(whereClause);

    const total = Number(countRow?.count || 0);

    const logs = await db
      .select()
      .from(schema.auditLogs)
      .where(whereClause)
      .orderBy(desc(schema.auditLogs.sequenceNumber))
      .limit(limit)
      .offset(offset);

    return NextResponse.json({
      logs,
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
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to query audit trail' } }, { status: 500 });
  }
}
