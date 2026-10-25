import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { softDeleteDocument, getDocumentWithAuthorization } from '@/server/services/documents';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { logAuditEvent } from '@/server/services/audit';
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
    const { action, documentIds, folderPath } = body;

    if (!action || !Array.isArray(documentIds) || documentIds.length === 0) {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'action ("delete" | "move") and non-empty documentIds array required' } },
        { status: 400 }
      );
    }

    const processed: string[] = [];
    const skipped: string[] = [];

    if (action === 'delete') {
      for (const id of documentIds) {
        try {
          await softDeleteDocument(user, id, ip, userAgent);
          processed.push(id);
        } catch {
          skipped.push(id);
        }
      }
    } else if (action === 'move') {
      const cleanFolder = (folderPath && typeof folderPath === 'string') ? folderPath.trim() : '/';
      for (const id of documentIds) {
        try {
          // Verify edit authorization
          await getDocumentWithAuthorization(user, id, 'edit', ip, userAgent);
          await db
            .update(schema.documents)
            .set({ folderPath: cleanFolder, updatedAt: new Date() })
            .where(eq(schema.documents.id, id));

          await logAuditEvent({
            actorId: user.id,
            actorEmail: user.email,
            actorRole: user.role,
            ipAddress: ip,
            userAgent,
            documentId: id,
            action: 'EDIT',
            outcome: 'ALLOWED',
            details: { movedToFolder: cleanFolder },
          });

          processed.push(id);
        } catch {
          skipped.push(id);
        }
      }
    } else {
      return NextResponse.json({ error: { code: 'INVALID_ACTION', message: 'Unsupported bulk action' } }, { status: 400 });
    }

    return NextResponse.json({
      success: true,
      processedCount: processed.length,
      skippedCount: skipped.length,
      processed,
      skipped,
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Bulk operation failed' } }, { status: 500 });
  }
}
