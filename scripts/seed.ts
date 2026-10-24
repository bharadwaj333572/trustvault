import { rawClient, db, schema } from '../src/server/db';
import { runMigrations } from '../src/server/db/migrate';
import { hashPassword } from '../src/server/auth/password';
import { computeRowHash } from '../src/server/services/audit';
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export const SEED_CREDENTIALS = {
  admin: {
    email: 'admin@trustvault.internal',
    password: 'AdminPassword123!',
    fullName: 'System Custodian Admin',
    role: 'ADMIN' as const,
  },
  owner1: {
    email: 'alice.owner@meridian.test',
    password: 'OwnerPassword123!',
    fullName: 'Alice Sterling (Owner)',
    role: 'OWNER' as const,
  },
  owner2: {
    email: 'bob.owner@apex.test',
    password: 'OwnerPassword456!',
    fullName: 'Bob Vance (Owner 2)',
    role: 'OWNER' as const,
  },
  viewer: {
    email: 'carol.viewer@auditcorp.test',
    password: 'ViewerPassword123!',
    fullName: 'Carol Danvers (Viewer)',
    role: 'VIEWER' as const,
  },
};

export async function seedDatabase() {
  console.log('--- Starting TrustVault Deterministic Seed ---');

  // Ensure migrations are run first
  await runMigrations();

  const storageDir = process.env.STORAGE_DIR || './storage';
  if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir, { recursive: true });
  }

  // Clear existing records in reverse dependency order
  const clearSql = `
    DELETE FROM document_grants;
    DELETE FROM document_versions;
    DELETE FROM documents;
    DELETE FROM sessions;
    -- Temporarily disable trigger on audit_logs for clean seed reset
    ALTER TABLE audit_logs DISABLE TRIGGER ALL;
    DELETE FROM audit_logs;
    ALTER TABLE audit_logs ENABLE TRIGGER ALL;
    DELETE FROM users;
  `;
  if ('exec' in (rawClient as any)) {
    await (rawClient as any).exec(clearSql);
  } else {
    await (rawClient as any).query(clearSql);
  }

  // 1. Create Users
  const userMap: Record<string, string> = {};

  for (const [key, u] of Object.entries(SEED_CREDENTIALS)) {
    const userId = randomUUID();
    userMap[key] = userId;
    const pwdHash = await hashPassword(u.password);

    await db.insert(schema.users).values({
      id: userId,
      email: u.email,
      passwordHash: pwdHash,
      fullName: u.fullName,
      role: u.role,
      isDisabled: false,
      failedLoginAttempts: 0,
      createdAt: new Date('2026-10-01T08:00:00Z'),
      updatedAt: new Date('2026-10-01T08:00:00Z'),
    });
  }

  console.log('✓ Seeded 4 primary users (1 Admin, 2 Owners, 1 Viewer).');

  // 2. Helper to write private files
  function writeStorageFile(content: string): { storageKey: string; checksum: string; size: number } {
    const storageKey = randomUUID();
    const filePath = path.join(storageDir, storageKey);
    const buffer = Buffer.from(content, 'utf-8');
    fs.writeFileSync(filePath, buffer);
    const checksum = crypto.createHash('sha256').update(buffer).digest('hex');
    return { storageKey, checksum, size: buffer.length };
  }

  // 3. Create Documents for Alice
  const doc1Data = writeStorageFile('CONFIDENTIAL MERIDIAN LOGISTICS AUDIT REPORT 2026\nQuarterly margins, carrier SLAs, and risk reserves.');
  const doc1Id = randomUUID();
  await db.insert(schema.documents).values({
    id: doc1Id,
    title: 'Meridian Logistics Q3 Financial Audit',
    originalFileName: 'meridian_q3_audit.pdf',
    mimeType: 'application/pdf',
    fileSize: doc1Data.size,
    storageKey: doc1Data.storageKey,
    sha256Checksum: doc1Data.checksum,
    category: 'FINANCIAL',
    folderPath: '/finance/2026',
    ownerId: userMap.owner1,
    isDeleted: false,
    currentVersion: 1,
    createdAt: new Date('2026-10-02T09:15:00Z'),
    updatedAt: new Date('2026-10-02T09:15:00Z'),
  });

  const doc2Data = writeStorageFile('MASTER SUPPLY AGREEMENT - STRICTLY CONFIDENTIAL\nBetween Meridian Logistics and Apex Defense Systems.');
  const doc2Id = randomUUID();
  await db.insert(schema.documents).values({
    id: doc2Id,
    title: 'Master Supply Agreement v2.1',
    originalFileName: 'master_supply_agreement.docx',
    mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    fileSize: doc2Data.size,
    storageKey: doc2Data.storageKey,
    sha256Checksum: doc2Data.checksum,
    category: 'LEGAL',
    folderPath: '/legal/contracts',
    ownerId: userMap.owner1,
    isDeleted: false,
    currentVersion: 1,
    createdAt: new Date('2026-10-03T11:30:00Z'),
    updatedAt: new Date('2026-10-03T11:30:00Z'),
  });

  // 4. Create Document for Bob (Owner 2) - Carol should NEVER be able to access this
  const doc3Data = writeStorageFile('APEX DEFENSE - PROJECT ZEPHYR HARDWARE SPECS\nProprietary guidance sensor schematics.');
  const doc3Id = randomUUID();
  await db.insert(schema.documents).values({
    id: doc3Id,
    title: 'Project Zephyr Hardware Schematics',
    originalFileName: 'project_zephyr_specs.pdf',
    mimeType: 'application/pdf',
    fileSize: doc3Data.size,
    storageKey: doc3Data.storageKey,
    sha256Checksum: doc3Data.checksum,
    category: 'TECHNICAL',
    folderPath: '/engineering/classified',
    ownerId: userMap.owner2,
    isDeleted: false,
    currentVersion: 1,
    createdAt: new Date('2026-10-04T14:00:00Z'),
    updatedAt: new Date('2026-10-04T14:00:00Z'),
  });

  console.log('✓ Seeded 3 encrypted documents across owners with real disk storage keys.');

  // 5. Create Grants: Alice grants Carol READ access to doc1
  await db.insert(schema.documentGrants).values({
    id: randomUUID(),
    documentId: doc1Id,
    userId: userMap.viewer,
    permission: 'READ',
    expiresAt: new Date('2026-12-31T23:59:59Z'),
    grantedBy: userMap.owner1,
    createdAt: new Date('2026-10-05T10:00:00Z'),
    updatedAt: new Date('2026-10-05T10:00:00Z'),
  });

  console.log('✓ Seeded grant: Alice granted Carol READ permission on Q3 Financial Audit.');

  // 6. Build the Cryptographic Audit Hash Chain
  const GENESIS_HASH = '0'.repeat(64);
  let currentPrevHash = GENESIS_HASH;

  const rawAuditEvents = [
    {
      id: randomUUID(),
      createdAt: new Date('2026-10-01T08:05:00Z'),
      actorId: userMap.admin,
      actorEmail: SEED_CREDENTIALS.admin.email,
      actorRole: 'ADMIN',
      ipAddress: '192.168.1.10',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TrustVault/1.0',
      documentId: null,
      action: 'LOGIN_SUCCESS',
      outcome: 'ALLOWED',
      reason: 'PASSWORD_AUTHENTICATED',
      details: JSON.stringify({ note: 'Initial system initialization' }),
      requestId: 'req_init_001',
    },
    {
      id: randomUUID(),
      createdAt: new Date('2026-10-02T09:10:00Z'),
      actorId: userMap.owner1,
      actorEmail: SEED_CREDENTIALS.owner1.email,
      actorRole: 'OWNER',
      ipAddress: '192.168.1.25',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      documentId: null,
      action: 'LOGIN_SUCCESS',
      outcome: 'ALLOWED',
      reason: 'PASSWORD_AUTHENTICATED',
      details: JSON.stringify({ mfa: 'none' }),
      requestId: 'req_auth_002',
    },
    {
      id: randomUUID(),
      createdAt: new Date('2026-10-02T09:15:00Z'),
      actorId: userMap.owner1,
      actorEmail: SEED_CREDENTIALS.owner1.email,
      actorRole: 'OWNER',
      ipAddress: '192.168.1.25',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      documentId: doc1Id,
      action: 'UPLOAD',
      outcome: 'ALLOWED',
      reason: 'DOCUMENT_CREATED',
      details: JSON.stringify({ title: 'Meridian Logistics Q3 Financial Audit', size: doc1Data.size }),
      requestId: 'req_up_003',
    },
    {
      id: randomUUID(),
      createdAt: new Date('2026-10-05T10:00:00Z'),
      actorId: userMap.owner1,
      actorEmail: SEED_CREDENTIALS.owner1.email,
      actorRole: 'OWNER',
      ipAddress: '192.168.1.25',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      documentId: doc1Id,
      action: 'GRANT',
      outcome: 'ALLOWED',
      reason: 'GRANT_ISSUED',
      details: JSON.stringify({ grantedTo: SEED_CREDENTIALS.viewer.email, permission: 'READ' }),
      requestId: 'req_gr_004',
    },
    {
      id: randomUUID(),
      createdAt: new Date('2026-10-05T10:05:00Z'),
      actorId: userMap.viewer,
      actorEmail: SEED_CREDENTIALS.viewer.email,
      actorRole: 'VIEWER',
      ipAddress: '10.0.0.44',
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64)',
      documentId: doc1Id,
      action: 'DOWNLOAD',
      outcome: 'ALLOWED',
      reason: 'POLICY_AUTHORIZED_GRANT',
      details: JSON.stringify({ permission: 'READ', bytesStreamed: doc1Data.size }),
      requestId: 'req_dl_005',
    },
    {
      id: randomUUID(),
      createdAt: new Date('2026-10-05T10:10:00Z'),
      actorId: userMap.viewer,
      actorEmail: SEED_CREDENTIALS.viewer.email,
      actorRole: 'VIEWER',
      ipAddress: '10.0.0.44',
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64)',
      documentId: doc3Id, // Bob's classified document!
      action: 'DENIED_ATTEMPT',
      outcome: 'DENIED',
      reason: 'UNAUTHORIZED_ACCESS_DENIED',
      details: JSON.stringify({ targetDocumentTitle: 'Project Zephyr Hardware Schematics', action: 'download' }),
      requestId: 'req_denied_006',
    },
  ];

  for (const event of rawAuditEvents) {
    const rowHash = computeRowHash(currentPrevHash, {
      id: event.id,
      createdAt: event.createdAt.toISOString(),
      actorId: event.actorId,
      actorEmail: event.actorEmail,
      action: event.action,
      outcome: event.outcome,
      documentId: event.documentId,
      reason: event.reason,
    });

    await db.insert(schema.auditLogs).values({
      ...event,
      prevHash: currentPrevHash,
      rowHash,
    });

    currentPrevHash = rowHash;
  }

  console.log(`✓ Seeded cryptographic audit hash chain (${rawAuditEvents.length} ordered blocks, tip: ${currentPrevHash.slice(0, 16)}...).`);
  console.log('--- TrustVault Seed Completed Successfully ---');
}

if (require.main === module) {
  seedDatabase()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Seed script failed:', err);
      process.exit(1);
    });
}
