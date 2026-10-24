export type ErrorCode = 
  | 'UNAUTHENTICATED'
  | 'UNAUTHORIZED'
  | 'NOT_FOUND'
  | 'VALIDATION_ERROR'
  | 'RATE_LIMITED'
  | 'LOCKED_OUT'
  | 'CONFLICT'
  | 'FILE_TOO_LARGE'
  | 'INVALID_FILE_TYPE'
  | 'AUDIT_INTEGRITY_VIOLATION'
  | 'INTERNAL_SERVER_ERROR';

export interface AppErrorPayload {
  code: ErrorCode;
  message: string;
  details?: unknown;
  requestId?: string;
}

export class AppError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: unknown;
  public readonly isOperational: boolean;
  public readonly auditReason?: string;

  constructor(opts: {
    code: ErrorCode;
    statusCode: number;
    message: string;
    details?: unknown;
    isOperational?: boolean;
    auditReason?: string;
  }) {
    super(opts.message);
    this.name = 'AppError';
    this.code = opts.code;
    this.statusCode = opts.statusCode;
    this.details = opts.details;
    this.isOperational = opts.isOperational ?? true;
    this.auditReason = opts.auditReason;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  toJSON(requestId?: string): { error: AppErrorPayload } {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
        ...(requestId ? { requestId } : {}),
      },
    };
  }
}

/**
 * Uniform 404 response used for BOTH genuinely missing resources AND unauthorized/forbidden resources
 * to prevent ID enumeration and metadata existence leakage.
 */
export class UniformNotFoundOrForbiddenError extends AppError {
  constructor(auditReason: string = 'RESOURCE_NOT_FOUND_OR_DENIED') {
    super({
      code: 'NOT_FOUND',
      statusCode: 404,
      message: 'Document or resource not found',
      auditReason,
    });
  }
}

export class UnauthenticatedError extends AppError {
  constructor(message: string = 'Authentication required', auditReason: string = 'NO_ACTIVE_SESSION') {
    super({
      code: 'UNAUTHENTICATED',
      statusCode: 401,
      message,
      auditReason,
    });
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: unknown) {
    super({
      code: 'VALIDATION_ERROR',
      statusCode: 400,
      message,
      details,
      auditReason: 'INPUT_VALIDATION_FAILED',
    });
  }
}

export class RateLimitedError extends AppError {
  constructor(retryAfterSeconds: number = 60) {
    super({
      code: 'RATE_LIMITED',
      statusCode: 429,
      message: `Too many requests. Please wait ${retryAfterSeconds} seconds before retrying.`,
      details: { retryAfterSeconds },
      auditReason: 'RATE_LIMIT_EXCEEDED',
    });
  }
}

export class AccountLockedOutError extends AppError {
  constructor(lockedUntilMinutes: number = 15) {
    super({
      code: 'LOCKED_OUT',
      statusCode: 423,
      message: `Account is temporarily locked due to repeated failed login attempts. Retry in ${lockedUntilMinutes} minutes.`,
      details: { lockedUntilMinutes },
      auditReason: 'ACCOUNT_LOCKOUT_TRIGGERED',
    });
  }
}

export class AuditIntegrityError extends AppError {
  constructor(message: string, details?: unknown) {
    super({
      code: 'AUDIT_INTEGRITY_VIOLATION',
      statusCode: 500,
      message,
      details,
      auditReason: 'AUDIT_CHAIN_INTEGRITY_BROKEN',
    });
  }
}
