import { pgTable, text, timestamp, boolean, integer, bigint, serial } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

export const UserRole = {
  ADMIN: 'ADMIN',
  OWNER: 'OWNER',
  VIEWER: 'VIEWER',
} as const;
export type UserRoleType = (typeof UserRole)[keyof typeof UserRole];

export const DocumentCategory = {
  LEGAL: 'LEGAL',
  FINANCIAL: 'FINANCIAL',
  TECHNICAL: 'TECHNICAL',
  EXECUTIVE: 'EXECUTIVE',
  CONFIDENTIAL: 'CONFIDENTIAL',
  OTHER: 'OTHER',
} as const;
export type DocumentCategoryType = (typeof DocumentCategory)[keyof typeof DocumentCategory];

export const GrantPermission = {
  READ: 'READ',
  EDIT: 'EDIT',
} as const;
export type GrantPermissionType = (typeof GrantPermission)[keyof typeof GrantPermission];

export const AuditOutcome = {
  ALLOWED: 'ALLOWED',
  DENIED: 'DENIED',
} as const;
export type AuditOutcomeType = (typeof AuditOutcome)[keyof typeof AuditOutcome];

export const AuditAction = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  LOGOUT: 'LOGOUT',
  UPLOAD: 'UPLOAD',
  VIEW: 'VIEW',
  DOWNLOAD: 'DOWNLOAD',
  EDIT: 'EDIT',
  NEW_VERSION: 'NEW_VERSION',
  DELETE: 'DELETE',
  RESTORE: 'RESTORE',
  GRANT: 'GRANT',
  REVOKE: 'REVOKE',
  ROLE_CHANGE: 'ROLE_CHANGE',
  USER_DISABLE: 'USER_DISABLE',
  SUGGESTION_SHOWN: 'SUGGESTION_SHOWN',
  SUGGESTION_ACCEPTED: 'SUGGESTION_ACCEPTED',
  SUGGESTION_REJECTED: 'SUGGESTION_REJECTED',
  DENIED_ATTEMPT: 'DENIED_ATTEMPT',
} as const;
export type AuditActionType = (typeof AuditAction)[keyof typeof AuditAction];

// 1. Users Table
export const users = pgTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  fullName: text('full_name').notNull(),
  role: text('role').notNull().default(UserRole.VIEWER),
  isDisabled: boolean('is_disabled').notNull().default(false),
  failedLoginAttempts: integer('failed_login_attempts').notNull().default(0),
  lockedUntil: timestamp('locked_until', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// 2. Sessions Table (Opaque random token, DB-backed for immediate revocation)
export const sessions = pgTable('sessions', {
  id: text('id').primaryKey(), // SHA-256 hash of the session token
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// 3. Documents Table
export const documents = pgTable('documents', {
  id: text('id').primaryKey(),
  title: text('title').notNull(),
  originalFileName: text('original_file_name').notNull(),
  mimeType: text('mime_type').notNull(),
  fileSize: bigint('file_size', { mode: 'number' }).notNull(),
  storageKey: text('storage_key').notNull().unique(), // Random UUID on disk
  sha256Checksum: text('sha256_checksum').notNull(),
  category: text('category').notNull().default(DocumentCategory.OTHER),
  folderPath: text('folder_path').notNull().default('/'),
  ownerId: text('owner_id').notNull().references(() => users.id),
  isDeleted: boolean('is_deleted').notNull().default(false),
  deletedAt: timestamp('deleted_at', { withTimezone: true }),
  currentVersion: integer('current_version').notNull().default(1),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// 4. Document Versions Table
export const documentVersions = pgTable('document_versions', {
  id: text('id').primaryKey(),
  documentId: text('document_id').notNull().references(() => documents.id, { onDelete: 'cascade' }),
  versionNumber: integer('version_number').notNull(),
  storageKey: text('storage_key').notNull().unique(),
  originalFileName: text('original_file_name').notNull(),
  fileSize: bigint('file_size', { mode: 'number' }).notNull(),
  sha256Checksum: text('sha256_checksum').notNull(),
  createdBy: text('created_by').notNull().references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// 5. Document Grants Table (Per-document named grants with optional expiry)
export const documentGrants = pgTable('document_grants', {
  id: text('id').primaryKey(),
  documentId: text('document_id').notNull().references(() => documents.id, { onDelete: 'cascade' }),
  userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  permission: text('permission').notNull().default(GrantPermission.READ), // READ | EDIT
  expiresAt: timestamp('expires_at', { withTimezone: true }),
  grantedBy: text('granted_by').notNull().references(() => users.id),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// 6. Audit Logs Table (Tamper-evident append-only hash chain)
export const auditLogs = pgTable('audit_logs', {
  sequenceNumber: serial('sequence_number').primaryKey(),
  id: text('id').notNull().unique(),
  prevHash: text('prev_hash').notNull(),
  rowHash: text('row_hash').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  actorId: text('actor_id').references(() => users.id, { onDelete: 'set null' }),
  actorEmail: text('actor_email'),
  actorRole: text('actor_role'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  documentId: text('document_id'),
  action: text('action').notNull(),
  outcome: text('outcome').notNull(), // ALLOWED | DENIED
  reason: text('reason'),
  details: text('details'), // JSON serialized
  requestId: text('request_id'),
});

// 7. Chain Checkpoints Table (External anchor and tail truncation detection)
export const chainCheckpoints = pgTable('chain_checkpoints', {
  id: text('id').primaryKey(),
  sequenceNumber: integer('sequence_number').notNull(),
  chainHeadHash: text('chain_head_hash').notNull(),
  checkpointType: text('checkpoint_type').notNull().default('PERIODIC'), // PERIODIC | ADMIN_VERIFY | EXTERNAL
  hmacSignature: text('hmac_signature').notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// Relationships
export const usersRelations = relations(users, ({ many }) => ({
  sessions: many(sessions),
  documents: many(documents),
  receivedGrants: many(documentGrants, { relationName: 'receivedGrants' }),
  issuedGrants: many(documentGrants, { relationName: 'issuedGrants' }),
  auditLogs: many(auditLogs),
}));

export const documentsRelations = relations(documents, ({ one, many }) => ({
  owner: one(users, { fields: [documents.ownerId], references: [users.id] }),
  versions: many(documentVersions),
  grants: many(documentGrants),
}));

export const documentGrantsRelations = relations(documentGrants, ({ one }) => ({
  document: one(documents, { fields: [documentGrants.documentId], references: [documents.id] }),
  user: one(users, { fields: [documentGrants.userId], references: [users.id], relationName: 'receivedGrants' }),
  grantor: one(users, { fields: [documentGrants.grantedBy], references: [users.id], relationName: 'issuedGrants' }),
}));

export const documentVersionsRelations = relations(documentVersions, ({ one }) => ({
  document: one(documents, { fields: [documentVersions.documentId], references: [documents.id] }),
  creator: one(users, { fields: [documentVersions.createdBy], references: [users.id] }),
}));

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  actor: one(users, { fields: [auditLogs.actorId], references: [users.id] }),
}));
