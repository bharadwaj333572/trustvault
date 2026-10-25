import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getDocumentWithAuthorization } from '@/server/services/documents';
import { db, schema } from '@/server/db';
import { eq, and } from 'drizzle-orm';
import { logAuditEvent } from '@/server/services/audit';
import { AppError, NotFoundError } from '@/server/errors';

export async function POST(
  req: NextRequest,
  { params }: { params: { id: string; versionId: string } }
) {
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

    // Owner-only action: use 'share' (owner-exclusive) so EDIT grantees get uniform 404, not 403.
    const { document } = await getDocumentWithAuthorization(user, params.id, 'share', ip, userAgent);

    // Fetch the target version
    const versionRecords = await db
      .select()
      .from(schema.documentVersions)
      .where(
        and(
          eq(schema.documentVersions.id, params.versionId),
          eq(schema.documentVersions.documentId, document.id)
        )
      )
      .limit(1);

    if (versionRecords.length === 0) {
      throw new NotFoundError('VERSION_NOT_FOUND', 'The requested document version does not exist.');
    }

    const targetVersion = versionRecords[0];
    const now = new Date();

    // Update active document pointer to restored version
    await db
      .update(schema.documents)
      .set({
        storageKey: targetVersion.storageKey,
        originalFileName: targetVersion.originalFileName,
        fileSize: targetVersion.fileSize,
        sha256Checksum: targetVersion.sha256Checksum,
        currentVersion: targetVersion.versionNumber,
        updatedAt: now,
      })
      .where(eq(schema.documents.id, document.id));

    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      documentId: document.id,
      action: 'VERSION_RESTORED',
      outcome: 'ALLOWED',
      details: {
        restoredVersionNumber: targetVersion.versionNumber,
        restoredVersionId: targetVersion.id,
      },
    });

    return NextResponse.json({
      success: true,
      message: `Version ${targetVersion.versionNumber} restored as the active version.`,
      currentVersion: targetVersion.versionNumber,
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to restore version' } }, { status: 500 });
  }
}
