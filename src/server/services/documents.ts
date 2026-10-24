import { db, schema } from '../db';
import { eq, and, sql, desc, or, ilike } from 'drizzle-orm';
import { can, PolicyGrant } from '../policy';
import { fileStorage } from '../storage';
import { validateUploadedFile } from '../validation/upload';
import { logAuditEvent } from './audit';
import { AuthenticatedUser } from '../auth/session';
import { AppError, UniformNotFoundOrForbiddenError, ValidationError } from '../errors';
import crypto from 'crypto';

export interface CreateDocumentInput {
  title: string;
  category?: 'LEGAL' | 'FINANCIAL' | 'TECHNICAL' | 'EXECUTIVE' | 'CONFIDENTIAL' | 'OTHER';
  folderPath?: string;
}

export interface ListDocumentsOptions {
  search?: string;
  category?: string;
  folderPath?: string;
  includeTrash?: boolean;
  limit?: number;
  offset?: number;
}

export async function createDocument(
  user: AuthenticatedUser,
  input: CreateDocumentInput,
  fileBuffer: Buffer,
  declaredFileName: string,
  declaredSize: number,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  // 1. Role enforcement: Viewers cannot upload
  if (user.role === 'VIEWER') {
    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: clientIp,
      userAgent,
      action: 'DENIED_ATTEMPT',
      outcome: 'DENIED',
      reason: 'VIEWER_CANNOT_UPLOAD',
      requestId,
    });
    throw new AppError({
      code: 'UNAUTHORIZED',
      statusCode: 403,
      message: 'Viewers do not have permission to upload documents to the vault.',
      auditReason: 'VIEWER_CANNOT_UPLOAD',
    });
  }

  // 2. Magic byte file validation
  const validation = validateUploadedFile(fileBuffer, declaredFileName, declaredSize);

  // 3. Persist file securely in private storage
  const storageResult = await fileStorage.writeBuffer(fileBuffer);

  const documentId = crypto.randomUUID();
  const now = new Date();

  // 4. Insert Document record (ignore any client-provided ownerId or role to prevent mass assignment)
  await db.insert(schema.documents).values({
    id: documentId,
    title: input.title.trim() || validation.sanitizedFileName,
    originalFileName: validation.sanitizedFileName,
    mimeType: validation.detectedMime,
    fileSize: storageResult.byteLength,
    storageKey: storageResult.storageKey,
    sha256Checksum: storageResult.sha256Checksum,
    category: input.category || 'OTHER',
    folderPath: input.folderPath?.trim() || '/',
    ownerId: user.id, // Strictly bound to authenticated session
    isDeleted: false,
    currentVersion: 1,
    createdAt: now,
    updatedAt: now,
  });

  // 5. Insert Version 1 record
  await db.insert(schema.documentVersions).values({
    id: crypto.randomUUID(),
    documentId,
    versionNumber: 1,
    storageKey: storageResult.storageKey,
    originalFileName: validation.sanitizedFileName,
    fileSize: storageResult.byteLength,
    sha256Checksum: storageResult.sha256Checksum,
    createdBy: user.id,
    createdAt: now,
  });

  // 6. Record upload event in cryptographic audit chain
  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: 'UPLOAD',
    outcome: 'ALLOWED',
    reason: 'DOCUMENT_CREATED',
    details: {
      title: input.title,
      fileName: validation.sanitizedFileName,
      mimeType: validation.detectedMime,
      fileSize: storageResult.byteLength,
      sha256Checksum: storageResult.sha256Checksum,
    },
    requestId,
  });

  return {
    id: documentId,
    title: input.title,
    originalFileName: validation.sanitizedFileName,
    mimeType: validation.detectedMime,
    fileSize: storageResult.byteLength,
    sha256Checksum: storageResult.sha256Checksum,
    category: input.category || 'OTHER',
    folderPath: input.folderPath || '/',
    currentVersion: 1,
  };
}

export async function getDocumentWithAuthorization(
  user: AuthenticatedUser,
  documentId: string,
  action: 'view' | 'download' | 'edit' | 'delete' | 'share' | 'viewActivity',
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  // Query document and owner details
  const docs = await db
    .select({
      id: schema.documents.id,
      title: schema.documents.title,
      originalFileName: schema.documents.originalFileName,
      mimeType: schema.documents.mimeType,
      fileSize: schema.documents.fileSize,
      storageKey: schema.documents.storageKey,
      sha256Checksum: schema.documents.sha256Checksum,
      category: schema.documents.category,
      folderPath: schema.documents.folderPath,
      ownerId: schema.documents.ownerId,
      ownerEmail: schema.users.email,
      ownerName: schema.users.fullName,
      isDeleted: schema.documents.isDeleted,
      deletedAt: schema.documents.deletedAt,
      currentVersion: schema.documents.currentVersion,
      createdAt: schema.documents.createdAt,
      updatedAt: schema.documents.updatedAt,
    })
    .from(schema.documents)
    .innerJoin(schema.users, eq(schema.documents.ownerId, schema.users.id))
    .where(eq(schema.documents.id, documentId))
    .limit(1);

  if (docs.length === 0) {
    // Audit denied attempt for missing document
    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: clientIp,
      userAgent,
      documentId,
      action: 'DENIED_ATTEMPT',
      outcome: 'DENIED',
      reason: 'DOCUMENT_DOES_NOT_EXIST',
      requestId,
    });
    throw new UniformNotFoundOrForbiddenError('DOCUMENT_DOES_NOT_EXIST');
  }

  const doc = docs[0];

  // Query grants for this document
  const rawGrants = await db
    .select()
    .from(schema.documentGrants)
    .where(eq(schema.documentGrants.documentId, documentId));

  const grants: PolicyGrant[] = rawGrants.map((g) => ({
    id: g.id,
    documentId: g.documentId,
    userId: g.userId,
    permission: g.permission as 'READ' | 'EDIT',
    expiresAt: g.expiresAt,
  }));

  // Central policy evaluation
  const decision = can(user, action, doc, grants);

  if (!decision.allowed) {
    // Record security denial in audit log
    await logAuditEvent({
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      ipAddress: clientIp,
      userAgent,
      documentId,
      action: 'DENIED_ATTEMPT',
      outcome: 'DENIED',
      reason: decision.reason,
      details: { attemptedAction: action, documentTitle: doc.title },
      requestId,
    });

    // Return uniform 404 to never leak document existence
    throw new UniformNotFoundOrForbiddenError(decision.reason);
  }

  return {
    document: doc,
    grants,
    decision,
  };
}

/**
 * List documents with strict SQL-level grant filtration.
 * Never fetches ungranted rows into application memory.
 */
export async function listAuthorizedDocuments(
  user: AuthenticatedUser,
  options: ListDocumentsOptions = {}
) {
  const limit = Math.min(options.limit || 50, 100);
  const offset = options.offset || 0;
  const now = new Date();

  // Build SQL authorization predicate:
  // User is owner OR user has an active, unexpired grant
  // Admins do NOT have wildcard visibility into private files.
  const authCondition = or(
    eq(schema.documents.ownerId, user.id),
    sql`${schema.documents.id} IN (
      SELECT ${schema.documentGrants.documentId} 
      FROM ${schema.documentGrants} 
      WHERE ${schema.documentGrants.userId} = ${user.id} 
      AND (${schema.documentGrants.expiresAt} IS NULL OR ${schema.documentGrants.expiresAt} > ${now})
    )`
  );

  const filters = [authCondition];

  // Trash filter
  if (options.includeTrash) {
    filters.push(eq(schema.documents.isDeleted, true));
    // Trash is only visible to the owner
    filters.push(eq(schema.documents.ownerId, user.id));
  } else {
    filters.push(eq(schema.documents.isDeleted, false));
  }

  // Category filter
  if (options.category) {
    filters.push(eq(schema.documents.category, options.category));
  }

  // Search filter
  if (options.search) {
    filters.push(ilike(schema.documents.title, `%${options.search}%`));
  }

  const results = await db
    .select({
      id: schema.documents.id,
      title: schema.documents.title,
      originalFileName: schema.documents.originalFileName,
      mimeType: schema.documents.mimeType,
      fileSize: schema.documents.fileSize,
      category: schema.documents.category,
      folderPath: schema.documents.folderPath,
      ownerId: schema.documents.ownerId,
      ownerEmail: schema.users.email,
      ownerName: schema.users.fullName,
      currentVersion: schema.documents.currentVersion,
      createdAt: schema.documents.createdAt,
      updatedAt: schema.documents.updatedAt,
    })
    .from(schema.documents)
    .innerJoin(schema.users, eq(schema.documents.ownerId, schema.users.id))
    .where(and(...filters))
    .orderBy(desc(schema.documents.updatedAt))
    .limit(limit)
    .offset(offset);

  return results;
}

/**
 * Soft deletes a document (Owner only).
 */
export async function softDeleteDocument(
  user: AuthenticatedUser,
  documentId: string,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  const { document } = await getDocumentWithAuthorization(user, documentId, 'delete', clientIp, userAgent, requestId);
  const now = new Date();

  await db
    .update(schema.documents)
    .set({
      isDeleted: true,
      deletedAt: now,
      updatedAt: now,
    })
    .where(eq(schema.documents.id, documentId));

  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: 'DELETE',
    outcome: 'ALLOWED',
    reason: 'DOCUMENT_SOFT_DELETED',
    details: { title: document.title },
    requestId,
  });

  return { success: true };
}

/**
 * Restores a soft-deleted document (Owner only).
 */
export async function restoreDocument(
  user: AuthenticatedUser,
  documentId: string,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  const docs = await db
    .select()
    .from(schema.documents)
    .where(eq(schema.documents.id, documentId))
    .limit(1);

  if (docs.length === 0 || docs[0].ownerId !== user.id) {
    throw new UniformNotFoundOrForbiddenError('DOCUMENT_NOT_FOUND_OR_NOT_OWNER');
  }

  const now = new Date();

  await db
    .update(schema.documents)
    .set({
      isDeleted: false,
      deletedAt: null,
      updatedAt: now,
    })
    .where(eq(schema.documents.id, documentId));

  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: 'RESTORE',
    outcome: 'ALLOWED',
    reason: 'DOCUMENT_RESTORED',
    requestId,
  });

  return { success: true };
}

/**
 * Uploads a new version of an existing document.
 * Requires EDIT permission or Owner.
 */
export async function createDocumentVersion(
  user: AuthenticatedUser,
  documentId: string,
  fileBuffer: Buffer,
  declaredFileName: string,
  declaredSize: number,
  clientIp?: string,
  userAgent?: string,
  requestId?: string
) {
  const { document } = await getDocumentWithAuthorization(user, documentId, 'edit', clientIp, userAgent, requestId);

  // Validate uploaded file magic bytes
  const validation = validateUploadedFile(fileBuffer, declaredFileName, declaredSize);

  // Persist new version file to storage
  const storageResult = await fileStorage.writeBuffer(fileBuffer);

  const nextVersionNumber = document.currentVersion + 1;
  const now = new Date();

  // Insert into document_versions
  await db.insert(schema.documentVersions).values({
    id: crypto.randomUUID(),
    documentId,
    versionNumber: nextVersionNumber,
    storageKey: storageResult.storageKey,
    originalFileName: validation.sanitizedFileName,
    fileSize: storageResult.byteLength,
    sha256Checksum: storageResult.sha256Checksum,
    createdBy: user.id,
    createdAt: now,
  });

  // Update current document pointer
  await db
    .update(schema.documents)
    .set({
      storageKey: storageResult.storageKey,
      fileSize: storageResult.byteLength,
      sha256Checksum: storageResult.sha256Checksum,
      originalFileName: validation.sanitizedFileName,
      mimeType: validation.detectedMime,
      currentVersion: nextVersionNumber,
      updatedAt: now,
    })
    .where(eq(schema.documents.id, documentId));

  await logAuditEvent({
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    ipAddress: clientIp,
    userAgent,
    documentId,
    action: 'NEW_VERSION',
    outcome: 'ALLOWED',
    reason: 'DOCUMENT_VERSION_UPLOADED',
    details: {
      versionNumber: nextVersionNumber,
      fileSize: storageResult.byteLength,
      sha256Checksum: storageResult.sha256Checksum,
    },
    requestId,
  });

  return {
    documentId,
    versionNumber: nextVersionNumber,
    fileSize: storageResult.byteLength,
    sha256Checksum: storageResult.sha256Checksum,
  };
}
