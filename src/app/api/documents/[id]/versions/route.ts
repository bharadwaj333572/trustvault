import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { getDocumentWithAuthorization, createDocumentVersion } from '@/server/services/documents';
import { db, schema } from '@/server/db';
import { eq, desc } from 'drizzle-orm';
import { AppError } from '@/server/errors';

export async function GET(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const cookieToken = req.cookies.get(SESSION_COOKIE_NAME)?.value;
    const authHeader = req.headers.get('authorization');
    const token = cookieToken || (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined);

    if (!token) {
      return NextResponse.json({ error: { code: 'UNAUTHENTICATED', message: 'Authentication required' } }, { status: 401 });
    }

    const { user } = await validateSession(token);
    // Requires view authorization
    await getDocumentWithAuthorization(user, params.id, 'view');

    const versions = await db
      .select({
        id: schema.documentVersions.id,
        versionNumber: schema.documentVersions.versionNumber,
        originalFileName: schema.documentVersions.originalFileName,
        fileSize: schema.documentVersions.fileSize,
        sha256Checksum: schema.documentVersions.sha256Checksum,
        createdAt: schema.documentVersions.createdAt,
        createdBy: schema.documentVersions.createdBy,
        creatorName: schema.users.fullName,
        creatorEmail: schema.users.email,
      })
      .from(schema.documentVersions)
      .innerJoin(schema.users, eq(schema.documentVersions.createdBy, schema.users.id))
      .where(eq(schema.documentVersions.documentId, params.id))
      .orderBy(desc(schema.documentVersions.versionNumber));

    return NextResponse.json({ versions });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to list versions' } }, { status: 500 });
  }
}

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
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

    // Authorize BEFORE body validation so missing-file cannot distinguish existence (uniform 404).
    await getDocumentWithAuthorization(user, params.id, 'edit', ip, userAgent);

    let formData: FormData;
    try {
      formData = await req.formData();
    } catch {
      return NextResponse.json(
        { error: { code: 'VALIDATION_ERROR', message: 'Expected multipart/form-data upload.' } },
        { status: 400 }
      );
    }
    const file = formData.get('file') as File | null;

    if (!file) {
      return NextResponse.json({ error: { code: 'VALIDATION_ERROR', message: 'Version file payload is required.' } }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const result = await createDocumentVersion(
      user,
      params.id,
      buffer,
      file.name,
      file.size,
      ip,
      userAgent
    );

    return NextResponse.json({ success: true, version: result }, { status: 201 });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to upload new version' } }, { status: 500 });
  }
}
