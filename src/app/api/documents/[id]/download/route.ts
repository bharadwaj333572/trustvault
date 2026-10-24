import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getDocumentWithAuthorization } from '@/server/services/documents';
import { fileStorage } from '@/server/storage';
import { logAuditEvent } from '@/server/services/audit';
import { db, schema } from '@/server/db';
import { eq, and } from 'drizzle-orm';
import { AppError, NotFoundError } from '@/server/errors';

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

    // 3. Resolve target storage key (current vs specific version)
    const { searchParams } = new URL(req.url);
    const versionParam = searchParams.get('version');
    let targetStorageKey = document.storageKey;
    let targetFileName = document.originalFileName;
    let targetChecksum = document.sha256Checksum;
    let downloadedVersion = document.currentVersion;

    if (versionParam) {
      const verNum = parseInt(versionParam, 10);
      if (isNaN(verNum)) {
        return NextResponse.json({ error: { code: 'VALIDATION_ERROR', message: 'Invalid version number' } }, { status: 400 });
      }

      const versionRecords = await db
        .select()
        .from(schema.documentVersions)
        .where(
          and(
            eq(schema.documentVersions.documentId, document.id),
            eq(schema.documentVersions.versionNumber, verNum)
          )
        )
        .limit(1);

      if (versionRecords.length === 0) {
        throw new NotFoundError('DOCUMENT_VERSION_NOT_FOUND', `Version ${verNum} does not exist for this document.`);
      }

      targetStorageKey = versionRecords[0].storageKey;
      targetFileName = versionRecords[0].originalFileName;
      targetChecksum = versionRecords[0].sha256Checksum;
      downloadedVersion = versionRecords[0].versionNumber;
    }

    // 4. Read file buffer from private storage
    const fileBuffer = await fileStorage.readBuffer(targetStorageKey);
    const totalSize = fileBuffer.length;

    // 5. Handle HTTP Range Requests (resumable downloads and chunked previews)
    const rangeHeader = req.headers.get('range');
    let statusCode = 200;
    let responseBuffer: Buffer = fileBuffer;
    let contentRangeHeader: string | undefined;

    if (rangeHeader && rangeHeader.startsWith('bytes=')) {
      const parts = rangeHeader.replace('bytes=', '').split('-');
      const start = parts[0] ? parseInt(parts[0], 10) : 0;
      const end = parts[1] ? parseInt(parts[1], 10) : totalSize - 1;

      if (start >= totalSize || end >= totalSize || start > end) {
        return new NextResponse(null, {
          status: 416,
          headers: {
            'Content-Range': `bytes */${totalSize}`,
          },
        });
      }

      responseBuffer = fileBuffer.subarray(start, end + 1);
      statusCode = 206;
      contentRangeHeader = `bytes ${start}-${end}/${totalSize}`;
    }

    // 6. Log successful download in the tamper-evident audit hash chain
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
        fileName: targetFileName,
        fileSize: responseBuffer.length,
        totalFileSize: totalSize,
        version: downloadedVersion,
        sha256Checksum: targetChecksum,
        range: rangeHeader || 'FULL_PAYLOAD',
      },
    });

    // 7. Construct secure HTTP response with mandatory security headers
    const sanitizedDownloadName = targetFileName.replace(/["\r\n]/g, '_');

    const headers: Record<string, string> = {
      'Content-Type': document.mimeType || 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${sanitizedDownloadName}"`,
      'Content-Length': responseBuffer.length.toString(),
      'Accept-Ranges': 'bytes',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store, no-cache, must-revalidate, private',
      'Pragma': 'no-cache',
    };

    if (contentRangeHeader) {
      headers['Content-Range'] = contentRangeHeader;
    }

    return new NextResponse(new Uint8Array(responseBuffer), {
      status: statusCode,
      headers,
    });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to download file' } }, { status: 500 });
  }
}
