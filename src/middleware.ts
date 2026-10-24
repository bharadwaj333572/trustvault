import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const method = request.method.toUpperCase();

  // 1. CSRF Protection for state-mutating requests
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const origin = request.headers.get('origin');
    const host = request.headers.get('host');

    if (origin && host) {
      try {
        const originUrl = new URL(origin);
        if (originUrl.host !== host) {
          return NextResponse.json(
            { error: { code: 'UNAUTHORIZED', message: 'CSRF Origin mismatch blocked' } },
            { status: 403 }
          );
        }
      } catch {
        return NextResponse.json(
          { error: { code: 'UNAUTHORIZED', message: 'Malformed origin header' } },
          { status: 403 }
        );
      }
    }
  }

  const response = NextResponse.next();

  // 2. Strict Security Headers
  // Strict Content Security Policy (frame-ancestors 'none' blocks clickjacking)
  response.headers.set(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; frame-ancestors 'none'; connect-src 'self';"
  );

  // Prevent MIME type sniffing
  response.headers.set('X-Content-Type-Options', 'nosniff');

  // Prevent clickjacking
  response.headers.set('X-Frame-Options', 'DENY');

  // Referrer policy
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Strict Transport Security (HSTS)
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

  // Permissions policy
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  return response;
}

export const config = {
  matcher: [
    // Apply to all routes except static files, favicon, etc.
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
};
