import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getDocumentWithAuthorization, softDeleteDocument } from '@/server/services/documents';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { AppError } from '@/server/errors';
import { logAuditEvent } from '@/server/services/audit';

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
    const { document, decision } = await getDocumentWithAuthorization(user, params.id, 'view', ip, userAgent);

    return NextResponse.json({
      document,
      effectivePermission: decision.effectivePermission,
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Request failed' } }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
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
    const { document } = await getDocumentWithAuthorization(user, params.id, 'edit', ip, userAgent);

    const body = await req.json();
    const updateData: Record<string, any> = {
      updatedAt: new Date(),
    };

    if (body.title && typeof body.title === 'string') {
      updateData.title = body.title.trim();
    }
    if (body.category && typeof body.category === 'string') {
      updateData.category = body.category;
    }
    if (body.folderPath && typeof body.folderPath === 'string') {
      updateData.folderPath = body.folderPath.trim();
    }

    await db
      .update(schema.documents)
      .set(updateData)
      .where(eq(schema.documents.id, document.id));

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      documentId: document.id,
      action: 'EDIT',
      outcome: 'ALLOWED',
      reason: 'METADATA_UPDATED',
      details: updateData,
    });

    return NextResponse.json({ success: true, message: 'Document updated successfully' });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Update failed' } }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest, { params }: { params: { id: string } }) {
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
    await softDeleteDocument(user, params.id, ip, userAgent);

    return NextResponse.json({ success: true, message: 'Document soft-deleted' });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Deletion failed' } }, { status: 500 });
  }
}
