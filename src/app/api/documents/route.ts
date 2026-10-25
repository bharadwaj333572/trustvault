import { NextRequest, NextResponse } from 'next/server';
import { validateSession, SESSION_COOKIE_NAME } from '@/server/auth/session';
import { createDocument, listAuthorizedDocuments } from '@/server/services/documents';
import { checkActionRateLimit } from '@/server/auth/rate-limit';
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
    checkActionRateLimit('search:' + user.id, 60, 60000);

    const { searchParams } = new URL(req.url);

    const search = searchParams.get('search') || undefined;
    const category = searchParams.get('category') || undefined;
    const includeTrash = searchParams.get('trash') === 'true';
    const limit = searchParams.get('limit') ? parseInt(searchParams.get('limit')!, 10) : 50;
    const offset = searchParams.get('offset') ? parseInt(searchParams.get('offset')!, 10) : 0;

    const documents = await listAuthorizedDocuments(user, {
      search,
      category,
      includeTrash,
      limit,
      offset,
    });

    return NextResponse.json({ documents });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: 'Failed to retrieve documents' } }, { status: 500 });
  }
}

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
    checkActionRateLimit('upload:' + user.id, 20, 60000);

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
    const title = (formData.get('title') as string) || '';
    const category = (formData.get('category') as any) || 'OTHER';
    const folderPath = (formData.get('folderPath') as string) || '/';

    if (!file) {
      return NextResponse.json({ error: { code: 'VALIDATION_ERROR', message: 'File payload is required.' } }, { status: 400 });
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    const result = await createDocument(
      user,
      { title: title.trim() || file.name, category, folderPath },
      buffer,
      file.name,
      file.size,
      ip,
      userAgent
    );

    return NextResponse.json({ success: true, document: result }, { status: 201 });
  } catch (err: any) {
    if (err instanceof AppError) {
      return NextResponse.json(err.toJSON(), { status: err.statusCode });
    }
    console.error('Document upload error:', err);
    return NextResponse.json({ error: { code: 'INTERNAL_SERVER_ERROR', message: err.message || 'Upload failed' } }, { status: 500 });
  }
}
