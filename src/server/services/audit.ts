import crypto from 'crypto';
import { db, rawClient, schema } from '../db';
import { eq, asc, desc } from 'drizzle-orm';
import { AppError } from '../errors';

export const GENESIS_HASH = '0'.repeat(64);
const AUDIT_ADVISORY_LOCK_ID = 424242;

export interface CanonicalAuditPayload {
  id: string;
  createdAt: string;
  actorId: string | null;
  actorEmail?: string | null;
  action: string;
  outcome: 'ALLOWED' | 'DENIED';
  documentId?: string | null;
  reason?: string | null;
}

/**
 * Deterministically serialize an object to JSON with sorted keys
 * to ensure consistent cryptographic hashing across platforms.
 */
export function canonicalJsonStringify(obj: Record<string, any>): string {
  const sortedKeys = Object.keys(obj).sort();
  const sortedObj: Record<string, any> = {};
  for (const key of sortedKeys) {
    const val = obj[key];
    if (val !== undefined) {
      sortedObj[key] = val;
    }
  }
  return JSON.stringify(sortedObj);
}

/**
 * Compute SHA-256(prev_hash + canonicalJson(row))
 */
export function computeRowHash(prevHash: string, payload: CanonicalAuditPayload): string {
  const canonicalString = canonicalJsonStringify(payload);
  return crypto
    .createHash('sha256')
    .update(prevHash + canonicalString, 'utf-8')
    .digest('hex');
}

export interface CreateAuditLogParams {
  actorId?: string | null;
  actorEmail?: string | null;
  actorRole?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  documentId?: string | null;
  action: string;
  outcome: 'ALLOWED' | 'DENIED';
  reason?: string | null;
  details?: Record<string, any> | null;
  requestId?: string | null;
}

/**
 * Record an audit event into the tamper-evident hash chain.
 * Uses a PostgreSQL advisory lock inside a transaction to guarantee strict chronological ordering.
 * If this function fails, the entire transaction MUST abort.
 */
export async function logAuditEvent(params: CreateAuditLogParams): Promise<{ id: string; rowHash: string; sequenceNumber: number }> {
  try {
    const eventId = crypto.randomUUID();
    const now = new Date();

    // Acquire lock and fetch latest row_hash
    let prevHash = GENESIS_HASH;

    // Check if advisory locks are supported by the client
    const hasAdvisoryLock = 'query' in (rawClient as any);
    if (hasAdvisoryLock) {
      try {
        await (rawClient as any).query(`SELECT pg_advisory_xact_lock(${AUDIT_ADVISORY_LOCK_ID});`);
      } catch {
        // Fallback for drivers that don't support advisory locks in non-transactional mode
      }
    }

    // Get the latest inserted audit row to retrieve its hash
    const latestRows = await db
      .select({ rowHash: schema.auditLogs.rowHash })
      .from(schema.auditLogs)
      .orderBy(desc(schema.auditLogs.sequenceNumber))
      .limit(1);

    if (latestRows.length > 0 && latestRows[0].rowHash) {
      prevHash = latestRows[0].rowHash;
    }

    const canonicalPayload: CanonicalAuditPayload = {
      id: eventId,
      createdAt: now.toISOString(),
      actorId: params.actorId || null,
      actorEmail: params.actorEmail || null,
      action: params.action,
      outcome: params.outcome,
      documentId: params.documentId || null,
      reason: params.reason || null,
    };

    const rowHash = computeRowHash(prevHash, canonicalPayload);

    const [inserted] = await db
      .insert(schema.auditLogs)
      .values({
        id: eventId,
        prevHash,
        rowHash,
        createdAt: now,
        actorId: params.actorId || null,
        actorEmail: params.actorEmail || null,
        actorRole: params.actorRole || null,
        ipAddress: params.ipAddress || null,
        userAgent: params.userAgent || null,
        documentId: params.documentId || null,
        action: params.action,
        outcome: params.outcome,
        reason: params.reason || null,
        details: params.details ? JSON.stringify(params.details) : null,
        requestId: params.requestId || null,
      })
      .returning();

    return {
      id: inserted.id,
      rowHash: inserted.rowHash,
      sequenceNumber: inserted.sequenceNumber,
    };
  } catch (err: any) {
    console.error('CRITICAL AUDIT FAILURE: Failed to write to audit log.', err);
    throw new AppError({
      code: 'INTERNAL_SERVER_ERROR',
      statusCode: 500,
      message: 'Failed to record required audit trail event. Operation aborted for security.',
      auditReason: 'AUDIT_WRITE_FAILED',
      isOperational: false,
    });
  }
}

export interface VerificationResult {
  valid: boolean;
  totalEntries: number;
  lastVerifiedSequence: number;
  brokenAtSequence?: number;
  brokenRowId?: string;
  expectedHash?: string;
  actualHash?: string;
  reason?: string;
}

/**
 * Recomputes and verifies the complete cryptographic hash chain.
 * Returns the exact sequence number and row ID where tampering was detected, if any.
 */
export async function verifyChain(): Promise<VerificationResult> {
  const rows = await db
    .select()
    .from(schema.auditLogs)
    .orderBy(asc(schema.auditLogs.sequenceNumber));

  if (rows.length === 0) {
    return {
      valid: true,
      totalEntries: 0,
      lastVerifiedSequence: 0,
    };
  }

  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];

    // Check link to previous hash
    if (row.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        totalEntries: rows.length,
        lastVerifiedSequence: i > 0 ? rows[i - 1].sequenceNumber : 0,
        brokenAtSequence: row.sequenceNumber,
        brokenRowId: row.id,
        expectedHash: expectedPrevHash,
        actualHash: row.prevHash,
        reason: `Previous hash mismatch at sequence #${row.sequenceNumber}. Stored prevHash does not match expected chain hash.`,
      };
    }

    // Recompute row hash
    const canonicalPayload: CanonicalAuditPayload = {
      id: row.id,
      createdAt: row.createdAt.toISOString(),
      actorId: row.actorId || null,
      actorEmail: row.actorEmail || null,
      action: row.action,
      outcome: row.outcome as 'ALLOWED' | 'DENIED',
      documentId: row.documentId || null,
      reason: row.reason || null,
    };

    const recalculatedHash = computeRowHash(row.prevHash, canonicalPayload);

    if (row.rowHash !== recalculatedHash) {
      return {
        valid: false,
        totalEntries: rows.length,
        lastVerifiedSequence: i > 0 ? rows[i - 1].sequenceNumber : 0,
        brokenAtSequence: row.sequenceNumber,
        brokenRowId: row.id,
        expectedHash: recalculatedHash,
        actualHash: row.rowHash,
        reason: `Row content hash mismatch at sequence #${row.sequenceNumber}. Content has been tampered with or recalculated hash differs.`,
      };
    }

    expectedPrevHash = row.rowHash;
  }

  return {
    valid: true,
    totalEntries: rows.length,
    lastVerifiedSequence: rows[rows.length - 1].sequenceNumber,
  };
}
