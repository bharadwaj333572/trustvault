import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';

/**
 * Serves the OpenAPI specification. Must not embed live document metadata.
 */
export async function GET() {
  const specPath = path.resolve(process.cwd(), 'docs', 'openapi.yaml');

  if (!fs.existsSync(specPath)) {
    return NextResponse.json(
      { error: { code: 'NOT_FOUND', message: 'OpenAPI specification is not available.' } },
      { status: 404 }
    );
  }

  const yaml = fs.readFileSync(specPath, 'utf8');

  return new NextResponse(yaml, {
    status: 200,
    headers: {
      'Content-Type': 'application/yaml; charset=utf-8',
      'Cache-Control': 'public, max-age=60',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
