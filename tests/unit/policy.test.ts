import { describe, it, expect } from 'vitest';
import { can, PolicyUser, PolicyDocument, PolicyGrant } from '@/server/policy';

describe('TrustVault Central Policy Engine: can()', () => {
  const aliceOwner: PolicyUser = {
    id: 'user-alice-111',
    email: 'alice@meridian.test',
    role: 'OWNER',
    isDisabled: false,
  };

  const bobOwner2: PolicyUser = {
    id: 'user-bob-222',
    email: 'bob@apex.test',
    role: 'OWNER',
    isDisabled: false,
  };

  const carolViewer: PolicyUser = {
    id: 'user-carol-333',
    email: 'carol@auditcorp.test',
    role: 'VIEWER',
    isDisabled: false,
  };

  const adminUser: PolicyUser = {
    id: 'user-admin-999',
    email: 'admin@trustvault.internal',
    role: 'ADMIN',
    isDisabled: false,
  };

  const disabledUser: PolicyUser = {
    id: 'user-disabled-444',
    email: 'eve@rogue.test',
    role: 'VIEWER',
    isDisabled: true,
  };

  const doc1: PolicyDocument = {
    id: 'doc-contract-001',
    title: 'Meridian Supply Agreement',
    ownerId: aliceOwner.id,
    isDeleted: false,
  };

  const deletedDoc: PolicyDocument = {
    id: 'doc-deleted-002',
    title: 'Old Draft Specs',
    ownerId: aliceOwner.id,
    isDeleted: true,
  };

  describe('1. Owner Permissions (Full Control)', () => {
    it('allows owner to perform all valid actions on active document', () => {
      const actions = ['view', 'download', 'edit', 'delete', 'share', 'viewActivity'] as const;
      for (const action of actions) {
        const decision = can(aliceOwner, action, doc1);
        expect(decision.allowed).toBe(true);
        expect(decision.reason).toBe('DOCUMENT_OWNER_ACCESS');
        expect(decision.effectivePermission).toBe('OWNER');
      }
    });

    it('denies non-owner (Bob) full control on Alices document without grants', () => {
      const actions = ['view', 'download', 'edit', 'delete', 'share', 'viewActivity'] as const;
      for (const action of actions) {
        const decision = can(bobOwner2, action, doc1);
        expect(decision.allowed).toBe(false);
      }
    });
  });

  describe('2. Admin Content Isolation (No Implicit God-Mode)', () => {
    it('denies Admin from reading or downloading documents without an explicit grant', () => {
      const viewDecision = can(adminUser, 'view', doc1);
      expect(viewDecision.allowed).toBe(false);
      expect(viewDecision.reason).toBe('ADMIN_CONTENT_ACCESS_BLOCKED_UNLESS_GRANTED');

      const downloadDecision = can(adminUser, 'download', doc1);
      expect(downloadDecision.allowed).toBe(false);
      expect(downloadDecision.reason).toBe('ADMIN_CONTENT_ACCESS_BLOCKED_UNLESS_GRANTED');
    });

    it('allows Admin to view and download IF explicitly granted like any other user', () => {
      const adminGrant: PolicyGrant = {
        id: 'grant-adm',
        documentId: doc1.id,
        userId: adminUser.id,
        permission: 'READ',
        expiresAt: null,
      };
      const decision = can(adminUser, 'download', doc1, [adminGrant]);
      expect(decision.allowed).toBe(true);
      expect(decision.reason).toBe('ACTIVE_READ_GRANT');
    });
  });

  describe('3. READ Grant Level', () => {
    const readGrant: PolicyGrant = {
      id: 'grant-read-01',
      documentId: doc1.id,
      userId: carolViewer.id,
      permission: 'READ',
      expiresAt: null,
    };

    it('allows READ granted user to view and download', () => {
      expect(can(carolViewer, 'view', doc1, [readGrant]).allowed).toBe(true);
      expect(can(carolViewer, 'download', doc1, [readGrant]).allowed).toBe(true);
    });

    it('strictly denies READ granted user from editing, deleting, or sharing', () => {
      expect(can(carolViewer, 'edit', doc1, [readGrant]).allowed).toBe(false);
      expect(can(carolViewer, 'delete', doc1, [readGrant]).allowed).toBe(false);
      expect(can(carolViewer, 'share', doc1, [readGrant]).allowed).toBe(false);
      expect(can(carolViewer, 'viewActivity', doc1, [readGrant]).allowed).toBe(false);
    });
  });

  describe('4. EDIT Grant Level', () => {
    const editGrant: PolicyGrant = {
      id: 'grant-edit-01',
      documentId: doc1.id,
      userId: carolViewer.id,
      permission: 'EDIT',
      expiresAt: null,
    };

    it('allows EDIT granted user to view, download, and edit', () => {
      expect(can(carolViewer, 'view', doc1, [editGrant]).allowed).toBe(true);
      expect(can(carolViewer, 'download', doc1, [editGrant]).allowed).toBe(true);
      expect(can(carolViewer, 'edit', doc1, [editGrant]).allowed).toBe(true);
    });

    it('strictly denies EDIT granted user from deleting or re-sharing the document', () => {
      expect(can(carolViewer, 'delete', doc1, [editGrant]).allowed).toBe(false);
      expect(can(carolViewer, 'share', doc1, [editGrant]).allowed).toBe(false);
    });
  });

  describe('5. Temporal Expiry Enforcement', () => {
    it('denies access if the grant expiration timestamp is in the past', () => {
      const pastDate = new Date('2026-01-01T00:00:00Z');
      const now = new Date('2026-10-24T12:00:00Z');

      const expiredGrant: PolicyGrant = {
        id: 'grant-expired',
        documentId: doc1.id,
        userId: carolViewer.id,
        permission: 'READ',
        expiresAt: pastDate,
      };

      const decision = can(carolViewer, 'download', doc1, [expiredGrant], now);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe('NO_ACTIVE_GRANT_FOR_USER');
    });

    it('allows access if grant expiration timestamp is in the future', () => {
      const futureDate = new Date('2026-12-31T23:59:59Z');
      const now = new Date('2026-10-24T12:00:00Z');

      const validGrant: PolicyGrant = {
        id: 'grant-valid',
        documentId: doc1.id,
        userId: carolViewer.id,
        permission: 'READ',
        expiresAt: futureDate,
      };

      const decision = can(carolViewer, 'download', doc1, [validGrant], now);
      expect(decision.allowed).toBe(true);
    });
  });

  describe('6. Disabled Account Handling', () => {
    it('instantly denies disabled user even if they are the document owner', () => {
      const disabledOwner: PolicyUser = { ...aliceOwner, isDisabled: true };
      const decision = can(disabledOwner, 'download', doc1);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe('ACCOUNT_DISABLED');
    });

    it('instantly denies disabled user even if they hold an active unexpired grant', () => {
      const grant: PolicyGrant = {
        id: 'grant-eve',
        documentId: doc1.id,
        userId: disabledUser.id,
        permission: 'EDIT',
        expiresAt: null,
      };
      const decision = can(disabledUser, 'download', doc1, [grant]);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe('ACCOUNT_DISABLED');
    });
  });

  describe('7. Soft-Deleted Documents', () => {
    it('denies granted non-owners from accessing soft-deleted documents', () => {
      const grant: PolicyGrant = {
        id: 'grant-carol',
        documentId: deletedDoc.id,
        userId: carolViewer.id,
        permission: 'EDIT',
        expiresAt: null,
      };
      const decision = can(carolViewer, 'download', deletedDoc, [grant]);
      expect(decision.allowed).toBe(false);
      expect(decision.reason).toBe('DOCUMENT_SOFT_DELETED');
    });

    it('allows owner to view or restore soft-deleted documents', () => {
      const viewDecision = can(aliceOwner, 'view', deletedDoc);
      expect(viewDecision.allowed).toBe(true);
      expect(viewDecision.reason).toBe('OWNER_TRASH_MANAGEMENT');

      const editDecision = can(aliceOwner, 'edit', deletedDoc);
      expect(editDecision.allowed).toBe(true);
    });
  });

  describe('8. Anonymous and Missing Users', () => {
    it('strictly denies unauthenticated requests', () => {
      expect(can(null, 'view', doc1).allowed).toBe(false);
      expect(can(undefined, 'download', doc1).allowed).toBe(false);
    });
  });
});
