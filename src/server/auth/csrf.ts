import { NextRequest } from 'next/server';
import { AppError } from '../errors';

/**
 * Validates Origin and Host headers for state-mutating HTTP methods
 * (POST, PUT, PATCH, DELETE) to defend against Cross-Site Request Forgery (CSRF).
 */
export function verifyCsrfOrigin(req: NextRequest): void {
  const method = req.method.toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return; // Safe idempotent methods
  }

  const origin = req.headers.get('origin');
  const host = req.headers.get('host');

  // If origin is present, ensure it matches host
  if (origin && host) {
    try {
      const originUrl = new URL(origin);
      if (originUrl.host !== host) {
        throw new AppError({
          code: 'UNAUTHORIZED',
          statusCode: 403,
          message: 'Cross-Site Request Forgery (CSRF) origin mismatch rejected.',
          auditReason: 'CSRF_ORIGIN_MISMATCH',
        });
      }
    } catch (err: any) {
      if (err instanceof AppError) throw err;
      throw new AppError({
        code: 'UNAUTHORIZED',
        statusCode: 403,
        message: 'Invalid request origin header.',
        auditReason: 'CSRF_MALFORMED_ORIGIN',
      });
    }
  }
}
