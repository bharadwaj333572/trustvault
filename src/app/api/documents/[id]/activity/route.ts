import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getDocumentWithAuthorization } from '@/server/services/documents';
import { db, schema } from '@/server/db';
import { eq, desc } from 'drizzle-orm';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
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
    // Requires viewActivity authorization (Owner)
    await getDocumentWithAuthorization(user, params.id, 'viewActivity', ip, userAgent);

    const logs = await db
      .select({
        sequenceNumber: schema.auditLogs.sequenceNumber,
        id: schema.auditLogs.id,
        createdAt: schema.auditLogs.createdAt,
        action: schema.auditLogs.action,
        outcome: schema.auditLogs.outcome,
        actorEmail: schema.auditLogs.actorEmail,
        actorRole: schema.auditLogs.actorRole,
        ipAddress: schema.auditLogs.ipAddress,
        reason: schema.auditLogs.reason,
        details: schema.auditLogs.details,
        prevHash: schema.auditLogs.prevHash,
        rowHash: schema.auditLogs.rowHash,
      })
      .from(schema.auditLogs)
      .where(eq(schema.auditLogs.documentId, params.id))
      .orderBy(desc(schema.auditLogs.sequenceNumber))
      .limit(100);

    return NextResponse.json({ logs });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to retrieve document activity' } }, { status: 500 });
  }
}
