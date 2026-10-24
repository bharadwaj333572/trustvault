import { db, schema } from '../db';
import { eq, and } from 'drizzle-orm';
import { getDocumentWithAuthorization } from './documents';
import { logAuditEvent } from './audit';
import { AuthenticatedUser } from '../auth/session';
import { AppError, ValidationError } from '../errors';
import crypto from 'crypto';

export interface CreateGrantInput {
  targetEmail: string;
  permission: 'READ' | 'EDIT';
  expiresAt?: string | null;
}

/**
 * Lists all grants for a document. Requires 'share' authorization (Owner).
 */
export async function listDocumentGrants(
  user: AuthenticatedUser,
  documentId: string,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  // Only owner can inspect grant settings
  await getDocumentWithAuthorization(user, documentId, 'share', clientIp, userAgent, requestId);

  const grants = await db
    .select({
      id: schema.documentGrants.id,
      documentId: schema.documentGrants.documentId,
      userId: schema.documentGrants.userId,
      userEmail: schema.users.email,
      userName: schema.users.fullName,
      userRole: schema.users.role,
      permission: schema.documentGrants.permission,
      expiresAt: schema.documentGrants.expiresAt,
      createdAt: schema.documentGrants.createdAt,
      updatedAt: schema.documentGrants.updatedAt,
    })
    .from(schema.documentGrants)
    .innerJoin(schema.users, eq(schema.documentGrants.userId, schema.users.id))
    .where(eq(schema.documentGrants.documentId, documentId));

  return grants;
}

/**
 * Creates or updates a per-document grant to a named user.
 * Takes effect immediately on the very next request.
 */
export async function createDocumentGrant(
  user: AuthenticatedUser,
  documentId: string,
  input: CreateGrantInput,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  const { document } = await getDocumentWithAuthorization(user, documentId, 'share', clientIp, userAgent, requestId);

  const normalizedEmail = input.targetEmail.toLowerCase().trim();

  // Find target user
  const targetUsers = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.email, normalizedEmail))
    .limit(1);

  if (targetUsers.length === 0) {
    throw new ValidationError(`User with email "${normalizedEmail}" not found in system.`);
  }

  const targetUser = targetUsers[0];

  if (targetUser.id === user.id) {
    throw new ValidationError('You already have implicit full control over your own document.');
  }

  if (targetUser.isDisabled) {
    throw new ValidationError(`Cannot grant permissions to disabled user account "${normalizedEmail}".`);
  }

  const now = new Date();
  const expiresAtDate = input.expiresAt ? new Date(input.expiresAt) : null;

  if (expiresAtDate && expiresAtDate.getTime() <= now.getTime()) {
    throw new ValidationError('Grant expiration date must be in the future.');
  }

  // Check if an existing grant exists
  const existingGrants = await db
    .select()
    .from(schema.documentGrants)
    .where(
      and(
        eq(schema.documentGrants.documentId, documentId),
        eq(schema.documentGrants.userId, targetUser.id)
      )
    )
    .limit(1);

  let grantId: string;

  if (existingGrants.length > 0) {
    grantId = existingGrants[0].id;
    await db
      .update(schema.documentGrants)
      .set({
        permission: input.permission,
        expiresAt: expiresAtDate,
        updatedAt: now,
      })
      .where(eq(schema.documentGrants.id, grantId));
  } else {
    grantId = crypto.randomUUID();
    await db.insert(schema.documentGrants).values({
      id: grantId,
      documentId,
      userId: targetUser.id,
      permission: input.permission,
      expiresAt: expiresAtDate,
      grantedBy: user.id,
      createdAt: now,
      updatedAt: now,
    });
  }

  // Log in immutable audit hash chain
  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: 'GRANT',
    outcome: 'ALLOWED',
    reason: 'GRANT_ISSUED_OR_UPDATED',
    details: {
      grantedToUserId: targetUser.id,
      grantedToEmail: targetUser.email,
      permission: input.permission,
      expiresAt: expiresAtDate?.toISOString() || null,
      documentTitle: document.title,
    },
    requestId,
  });

  return {
    id: grantId,
    documentId,
    userId: targetUser.id,
    userEmail: targetUser.email,
    permission: input.permission,
    expiresAt: expiresAtDate,
  };
}

/**
 * Revokes a document grant immediately.
 * Takes effect on the very next millisecond for any download, view, or stream attempt.
 */
export async function revokeDocumentGrant(
  user: AuthenticatedUser,
  documentId: string,
  grantId: string,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  const { document } = await getDocumentWithAuthorization(user, documentId, 'share', clientIp, userAgent, requestId);

  // Retrieve grant details for audit logging
  const grants = await db
    .select({
      id: schema.documentGrants.id,
      userId: schema.documentGrants.userId,
      userEmail: schema.users.email,
      permission: schema.documentGrants.permission,
    })
    .from(schema.documentGrants)
    .innerJoin(schema.users, eq(schema.documentGrants.userId, schema.users.id))
    .where(
      and(
        eq(schema.documentGrants.id, grantId),
        eq(schema.documentGrants.documentId, documentId)
      )
    )
    .limit(1);

  if (grants.length === 0) {
    throw new AppError({
      code: 'NOT_FOUND',
      statusCode: 404,
      message: 'Grant not found on this document.',
    });
  }

  const grant = grants[0];

  // Delete grant from DB
  await db
    .delete(schema.documentGrants)
    .where(eq(schema.documentGrants.id, grantId));

  // Log revoke in audit hash chain
  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: 'REVOKE',
    outcome: 'ALLOWED',
    reason: 'GRANT_REVOKED',
    details: {
      revokedUserId: grant.userId,
      revokedUserEmail: grant.userEmail,
      revokedPermission: grant.permission,
      documentTitle: document.title,
    },
    requestId,
  });

  return {
    success: true,
    message: `Access revoked for ${grant.userEmail}. Revocation is active immediately.`,
  };
}
