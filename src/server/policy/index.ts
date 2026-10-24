import { UserRoleType, GrantPermissionType } from '../db/schema';

export type PolicyAction = 
  | 'view' 
  | 'download' 
  | 'edit' 
  | 'delete' 
  | 'share' 
  | 'viewActivity';

export interface PolicyUser {
  id: string;
  email: string;
  role: UserRoleType;
  isDisabled: boolean;
}

export interface PolicyDocument {
  id: string;
  title: string;
  ownerId: string;
  isDeleted: boolean;
}

export interface PolicyGrant {
  id: string;
  documentId: string;
  userId: string;
  permission: GrantPermissionType;
  expiresAt: Date | string | null;
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
  effectivePermission?: 'OWNER' | GrantPermissionType;
}

/**
 * TrustVault Central Policy Engine
 * SINGLE CHOKEPOINT for all authorization decisions.
 * Every route handler, server action, and file stream MUST call this function.
 * 
 * Rules:
 * 1. Default: DENY.
 * 2. Disabled users: DENY immediately.
 * 3. Soft-deleted documents: Only OWNER can view or restore/delete. All other access: DENY.
 * 4. Owner: Implicit full control (view, download, edit, delete, share, viewActivity).
 * 5. Admin: CANNOT read/download/edit/share documents unless explicitly granted like any other user.
 * 6. Named Grants:
 *    - READ: view, download.
 *    - EDIT: view, download, edit.
 *    - Expired grants (expiresAt <= now): DENY.
 * 7. Non-granted users: DENY.
 */
export function can(
  user: PolicyUser | null | undefined,
  action: PolicyAction,
  document: PolicyDocument,
  grants: PolicyGrant[] = [],
  currentTime: Date = new Date()
): PolicyDecision {
  // 1. Unauthenticated or missing user
  if (!user) {
    return {
      allowed: false,
      reason: 'UNAUTHENTICATED_ACCESS',
    };
  }

  // 2. Disabled account check (immediate revocation)
  if (user.isDisabled) {
    return {
      allowed: false,
      reason: 'ACCOUNT_DISABLED',
    };
  }

  const isOwner = document.ownerId === user.id;

  // 3. Soft-deleted documents
  if (document.isDeleted) {
    if (isOwner && (action === 'view' || action === 'delete' || action === 'edit')) {
      return {
        allowed: true,
        reason: 'OWNER_TRASH_MANAGEMENT',
        effectivePermission: 'OWNER',
      };
    }
    return {
      allowed: false,
      reason: 'DOCUMENT_SOFT_DELETED',
    };
  }

  // 4. Owner has full control
  if (isOwner) {
    return {
      allowed: true,
      reason: 'DOCUMENT_OWNER_ACCESS',
      effectivePermission: 'OWNER',
    };
  }

  // 5. Look for active, unexpired grant for this user on this document
  const activeGrant = grants.find((g) => {
    if (g.userId !== user.id || g.documentId !== document.id) {
      return false;
    }
    if (g.expiresAt) {
      const expiry = typeof g.expiresAt === 'string' ? new Date(g.expiresAt) : g.expiresAt;
      if (expiry.getTime() <= currentTime.getTime()) {
        return false; // Grant has expired
      }
    }
    return true;
  });

  // 6. Evaluate based on active grant level
  if (activeGrant) {
    if (activeGrant.permission === 'EDIT') {
      // EDIT allows view, download, and edit
      if (action === 'view' || action === 'download' || action === 'edit') {
        return {
          allowed: true,
          reason: 'ACTIVE_EDIT_GRANT',
          effectivePermission: 'EDIT',
        };
      }
      return {
        allowed: false,
        reason: 'EDIT_GRANT_CANNOT_DELETE_OR_SHARE',
      };
    }

    if (activeGrant.permission === 'READ') {
      // READ allows view and download
      if (action === 'view' || action === 'download') {
        return {
          allowed: true,
          reason: 'ACTIVE_READ_GRANT',
          effectivePermission: 'READ',
        };
      }
      return {
        allowed: false,
        reason: 'READ_GRANT_CANNOT_EDIT_OR_DELETE',
      };
    }
  }

  // 7. Admin role isolation: Admins do NOT possess implicit access to document content
  if (user.role === 'ADMIN') {
    return {
      allowed: false,
      reason: 'ADMIN_CONTENT_ACCESS_BLOCKED_UNLESS_GRANTED',
    };
  }

  // 8. Default DENY for all ungranted users
  return {
    allowed: false,
    reason: 'NO_ACTIVE_GRANT_FOR_USER',
  };
}
