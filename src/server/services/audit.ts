import crypto from 'crypto';
import { db, rawClient, schema } from '../db';
import { eq, asc, desc } from 'drizzle-orm';
import { AppError } from '../errors';

export const GENESIS_HASH = '0'.repeat(64);
const AUDIT_ADVISORY_LOCK_ID = 424242;
export const CHECKPOINT_INTERVAL = 10;

const AUDIT_HMAC_SECRET =
  process.env.AUDIT_HMAC_SECRET ||
  process.env.SESSION_SECRET ||
  'trustvault-tamper-proof-audit-hmac-secret-default-key-production';

// Strict FIFO async mutex to ensure 100% serialized in-process hash chaining under high concurrency
let chainLock: Promise<void> = Promise.resolve();

export async function acquireChainLock<T>(fn: () => Promise<T>): Promise<T> {
  const previousLock = chainLock;
  let release: () => void;
  chainLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previousLock;
  try {
    return await fn();
  } finally {
    release!();
  }
}

/**
 * Sanitizes strings for audit logging to prevent newline / CRLF log injection attacks.
 */
export function sanitizeLogString(val: string | null | undefined): string | null {
  if (val === null || val === undefined) return null;
  if (typeof val !== 'string') return String(val);
  return val.replace(/[\r\n\x00-\x1f\x7f]/g, ' ').trim();
}

/**
 * Recursively sanitizes JSON details payload for audit logging.
 */
export function sanitizeLogDetails(details: Record<string, any> | null | undefined): Record<string, any> | null {
  if (!details || typeof details !== 'object') return null;
  const clean: Record<string, any> = {};
  for (const [k, v] of Object.entries(details)) {
    const cleanKey = sanitizeLogString(k) || 'key';
    if (typeof v === 'string') {
      clean[cleanKey] = sanitizeLogString(v);
    } else if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      clean[cleanKey] = sanitizeLogDetails(v);
    } else if (Array.isArray(v)) {
      clean[cleanKey] = v.map((item) => (typeof item === 'string' ? sanitizeLogString(item) : item));
    } else {
      clean[cleanKey] = v;
    }
  }
  return clean;
}

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

/**
 * Computes HMAC-SHA256 signature for a checkpoint anchor
 */
export function signCheckpoint(sequenceNumber: number, chainHeadHash: string, createdAtIso: string): string {
  return crypto
    .createHmac('sha256', AUDIT_HMAC_SECRET)
    .update(`${sequenceNumber}:${chainHeadHash}:${createdAtIso}`, 'utf-8')
    .digest('hex');
}

/**
 * Creates and stores a signed checkpoint to serve as an anchor against tail truncation
 */
export async function createCheckpoint(
  sequenceNumber: number,
  chainHeadHash: string,
  checkpointType: 'PERIODIC' | 'ADMIN_VERIFY' | 'EXTERNAL' = 'PERIODIC'
) {
  const now = new Date();
  const nowIso = now.toISOString();
  const hmacSignature = signCheckpoint(sequenceNumber, chainHeadHash, nowIso);
  const id = crypto.randomUUID();

  const [checkpoint] = await db
    .insert(schema.chainCheckpoints)
    .values({
      id,
      sequenceNumber,
      chainHeadHash,
      checkpointType,
      hmacSignature,
      createdAt: now,
    })
    .returning();

  return checkpoint;
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
 * Uses a FIFO async mutex and PostgreSQL advisory lock to guarantee strict chronological ordering under concurrency.
 * If this function fails, the entire transaction MUST abort.
 */
export async function logAuditEvent(params: CreateAuditLogParams): Promise<{ id: string; rowHash: string; sequenceNumber: number }> {
  return acquireChainLock(async () => {
    try {
      const eventId = crypto.randomUUID();
      const now = new Date();

      // Sanitization to eliminate log injection
      const cleanAction = sanitizeLogString(params.action) || 'UNKNOWN_ACTION';
      const cleanReason = sanitizeLogString(params.reason);
      const cleanActorEmail = sanitizeLogString(params.actorEmail);
      const cleanIp = sanitizeLogString(params.ipAddress);
      const cleanUserAgent = sanitizeLogString(params.userAgent);
      const cleanDetails = sanitizeLogDetails(params.details);

      // Acquire advisory lock if supported
      const hasAdvisoryLock = 'query' in (rawClient as any);
      if (hasAdvisoryLock) {
        try {
          await (rawClient as any).query(`SELECT pg_advisory_xact_lock(${AUDIT_ADVISORY_LOCK_ID});`);
        } catch {
          // Fallback for drivers that don't support advisory locks in non-transactional mode
        }
      }

      // Fetch the latest inserted audit row to retrieve its hash
      let prevHash = GENESIS_HASH;
      const latestRows = await db
        .select({ rowHash: schema.auditLogs.rowHash, sequenceNumber: schema.auditLogs.sequenceNumber })
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
        actorEmail: cleanActorEmail,
        action: cleanAction,
        outcome: params.outcome,
        documentId: params.documentId || null,
        reason: cleanReason,
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
          actorEmail: cleanActorEmail,
          actorRole: sanitizeLogString(params.actorRole),
          ipAddress: cleanIp,
          userAgent: cleanUserAgent,
          documentId: params.documentId || null,
          action: cleanAction,
          outcome: params.outcome,
          reason: cleanReason,
          details: cleanDetails ? JSON.stringify(cleanDetails) : null,
          requestId: sanitizeLogString(params.requestId),
        })
        .returning();

      // Periodically anchor the chain via signed checkpoint
      if (inserted.sequenceNumber % CHECKPOINT_INTERVAL === 0) {
        try {
          await createCheckpoint(inserted.sequenceNumber, inserted.rowHash, 'PERIODIC');
        } catch (cpErr) {
          console.warn('Warning: Periodic checkpoint creation failed:', cpErr);
        }
      }

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
  });
}

export interface VerificationResult {
  valid: boolean;
  totalEntries: number;
  lastVerifiedSequence: number;
  brokenAtSequence?: number;
  brokenRowId?: string;
  expectedHash?: string;
  actualHash?: string;
  truncated?: boolean;
  expectedSequence?: number;
  actualSequence?: number;
  reason?: string;
  checkpoint?: any;
}

/**
 * Recomputes and verifies the complete cryptographic hash chain.
 * Checks row-by-row hash validity AND compares live head against latest signed checkpoint
 * to detect tail row deletion (truncation).
 */
export async function verifyChain(): Promise<VerificationResult> {
  const rows = await db
    .select()
    .from(schema.auditLogs)
    .orderBy(asc(schema.auditLogs.sequenceNumber));

  if (rows.length === 0) {
    // Check if there was supposed to be a checkpoint
    const latestCheckpoints = await db
      .select()
      .from(schema.chainCheckpoints)
      .orderBy(desc(schema.chainCheckpoints.sequenceNumber))
      .limit(1);

    if (latestCheckpoints.length > 0 && latestCheckpoints[0].sequenceNumber > 0) {
      return {
        valid: false,
        totalEntries: 0,
        lastVerifiedSequence: 0,
        truncated: true,
        expectedSequence: latestCheckpoints[0].sequenceNumber,
        actualSequence: 0,
        reason: `TRUNCATED: expected #${latestCheckpoints[0].sequenceNumber}, found #0`,
      };
    }

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

  const lastVerifiedSequence = rows[rows.length - 1].sequenceNumber;
  const liveHeadHash = rows[rows.length - 1].rowHash;

  // TRUNCATION DETECTION: Compare against latest signed checkpoint
  const latestCheckpoints = await db
    .select()
    .from(schema.chainCheckpoints)
    .orderBy(desc(schema.chainCheckpoints.sequenceNumber))
    .limit(1);

  if (latestCheckpoints.length > 0) {
    const cp = latestCheckpoints[0];

    // Verify HMAC of the checkpoint
    const expectedSig = signCheckpoint(cp.sequenceNumber, cp.chainHeadHash, cp.createdAt.toISOString());
    if (cp.hmacSignature !== expectedSig) {
      return {
        valid: false,
        totalEntries: rows.length,
        lastVerifiedSequence,
        reason: `CHECKPOINT_SIGNATURE_INVALID: The signature for checkpoint sequence #${cp.sequenceNumber} has been tampered with.`,
      };
    }

    // Check if live chain is shorter than checkpoint (tail deletion!)
    if (cp.sequenceNumber > lastVerifiedSequence) {
      return {
        valid: false,
        totalEntries: rows.length,
        lastVerifiedSequence,
        truncated: true,
        expectedSequence: cp.sequenceNumber,
        actualSequence: lastVerifiedSequence,
        reason: `TRUNCATED: expected #${cp.sequenceNumber}, found #${lastVerifiedSequence}`,
      };
    }
  }

  // Anchor this verification by writing an ADMIN_VERIFY checkpoint
  let newCheckpoint;
  try {
    newCheckpoint = await createCheckpoint(lastVerifiedSequence, liveHeadHash, 'ADMIN_VERIFY');
  } catch (err) {
    // Non-fatal if checkpoint write fails
  }

  return {
    valid: true,
    totalEntries: rows.length,
    lastVerifiedSequence,
    checkpoint: newCheckpoint,
  };
}
