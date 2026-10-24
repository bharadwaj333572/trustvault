import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getDocumentWithAuthorization } from '@/server/services/documents';
import { fileStorage } from '@/server/storage';
import { logAuditEvent } from '@/server/services/audit';
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

    // 1. Fresh database query on EVERY download request (verifies user active and not disabled)
    const { user } = await validateSession(token);

    // 2. Fresh central policy evaluation on EVERY download request (verifies active, unexpired grant)
    const { document } = await getDocumentWithAuthorization(user, params.id, 'download', ip, userAgent);

    // 3. Read file buffer or stream from private storage
    const fileBuffer = await fileStorage.readBuffer(document.storageKey);

    // 4. Log successful download in the tamper-evident audit hash chain
    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: ip,
      userAgent,
      documentId: document.id,
      action: 'DOWNLOAD',
      outcome: 'ALLOWED',
      reason: 'POLICY_AUTHORIZED_DOWNLOAD',
      details: {
        fileName: document.originalFileName,
        fileSize: fileBuffer.length,
        sha256Checksum: document.sha256Checksum,
      },
    });

    // 5. Construct secure HTTP response with mandatory security headers
    // Prevent inline XSS rendering (never inline HTML/SVG/executables)
    const sanitizedDownloadName = document.originalFileName.replace(/["\r\n]/g, '_');

    return new NextResponse(fileBuffer, {
      status: 200,
      headers: {
        'Content-Type': document.mimeType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${sanitizedDownloadName}"`,
        'Content-Length': fileBuffer.length.toString(),
        'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'no-store, no-cache, must-revalidate, private',
        'Pragma': 'no-cache',
      },
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to download file' } }, { status: 500 });
  }
}
