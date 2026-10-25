import type { HttpMethod } from './discover-routes';

/**
 * Actors exercised against Owner A's private document in the route inventory suite.
 */
export type InventoryActor =
  | 'ownerA'
  | 'ownerB'
  | 'viewer'
  | 'admin'
  | 'anonymous'
  | 'disabled';

export type StatusExpectation = number | number[];

export interface RouteInventoryEntry {
  method: HttpMethod;
  pathTemplate: string;
  /**
   * How the matrix probe is constructed:
   * - document: substitutes :id (and related) with Owner A's document
   * - auth: session/login style routes
   * - admin: admin-only operational routes
   * - public: no auth required
   * - collection: list/search/upload style (no foreign doc id in path)
   */
  kind: 'document' | 'auth' | 'admin' | 'public' | 'collection';
  /** Expected HTTP status per actor when probing Owner A's document (or equivalent). */
  expected: Record<InventoryActor, StatusExpectation>;
  /** Response must not reveal Owner A document title/metadata to unauthorized actors. */
  forbidDocMetaLeak?: boolean;
  notes?: string;
}

function s(...codes: number[]): StatusExpectation {
  return codes.length === 1 ? codes[0]! : codes;
}

/**
 * Canonical inventory of every HTTP handler. The security suite fails if the
 * filesystem discovers a method+path that is missing from this list.
 */
export const ROUTE_INVENTORY: RouteInventoryEntry[] = [
  // --- Auth ---
  {
    method: 'POST',
    pathTemplate: '/api/auth/login',
    kind: 'auth',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 401, // wrong/missing credentials shape exercised separately; probe uses empty body → 400/401
      disabled: 403,
    },
    notes: 'Login probe for disabled uses disabled credentials; anonymous uses invalid body.',
  },
  {
    method: 'POST',
    pathTemplate: '/api/auth/logout',
    kind: 'auth',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 200, // idempotent logout
      disabled: 200, // stale token still clears cookie
    },
  },
  {
    method: 'GET',
    pathTemplate: '/api/auth/me',
    kind: 'auth',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'GET',
    pathTemplate: '/api/auth/sessions',
    kind: 'auth',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'DELETE',
    pathTemplate: '/api/auth/sessions',
    kind: 'auth',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'POST',
    pathTemplate: '/api/auth/password',
    kind: 'auth',
    expected: {
      ownerA: s(200, 400),
      ownerB: s(200, 400),
      viewer: s(200, 400),
      admin: s(200, 400),
      anonymous: 401,
      disabled: 401,
    },
    notes: 'Password change requires current+new password; empty body → 400 for authed users.',
  },

  // --- Documents collection ---
  {
    method: 'GET',
    pathTemplate: '/api/documents',
    kind: 'collection',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'POST',
    pathTemplate: '/api/documents',
    kind: 'collection',
    expected: {
      ownerA: s(200, 201, 400),
      ownerB: s(200, 201, 400),
      viewer: s(403, 400),
      admin: s(200, 201, 400),
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'POST',
    pathTemplate: '/api/documents/bulk',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 200, // skips unauthorized ids
      viewer: 200,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
    notes: 'Bulk skips unauthorized IDs; must not leak titles of Owner A docs to others.',
  },

  // --- Document resource ---
  {
    method: 'GET',
    pathTemplate: '/api/documents/:id',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'PATCH',
    pathTemplate: '/api/documents/:id',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'DELETE',
    pathTemplate: '/api/documents/:id',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'GET',
    pathTemplate: '/api/documents/:id/download',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'POST',
    pathTemplate: '/api/documents/:id/restore',
    kind: 'document',
    expected: {
      ownerA: s(200, 400, 404), // 400 if not in trash
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'GET',
    pathTemplate: '/api/documents/:id/activity',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'GET',
    pathTemplate: '/api/documents/:id/grants',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'POST',
    pathTemplate: '/api/documents/:id/grants',
    kind: 'document',
    expected: {
      ownerA: s(200, 201, 400),
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'DELETE',
    pathTemplate: '/api/documents/:id/grants/:grantId',
    kind: 'document',
    expected: {
      ownerA: s(200, 404),
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'GET',
    pathTemplate: '/api/documents/:id/versions',
    kind: 'document',
    expected: {
      ownerA: 200,
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'POST',
    pathTemplate: '/api/documents/:id/versions',
    kind: 'document',
    expected: {
      ownerA: s(200, 201, 400),
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'POST',
    pathTemplate: '/api/documents/:id/versions/:versionId/restore',
    kind: 'document',
    expected: {
      ownerA: s(200, 404),
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },

  // --- Search / suggestions / autocomplete ---
  {
    method: 'GET',
    pathTemplate: '/api/search',
    kind: 'collection',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'GET',
    pathTemplate: '/api/suggestions',
    kind: 'document',
    expected: {
      ownerA: s(200, 400),
      ownerB: 404,
      viewer: 404,
      admin: 404,
      anonymous: 401,
      disabled: 401,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'POST',
    pathTemplate: '/api/suggestions/feedback',
    kind: 'auth',
    expected: {
      ownerA: s(200, 400),
      ownerB: s(200, 400),
      viewer: s(200, 400),
      admin: s(200, 400),
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'GET',
    pathTemplate: '/api/users/autocomplete',
    kind: 'collection',
    expected: {
      ownerA: s(200, 400),
      ownerB: s(200, 400),
      viewer: s(200, 400),
      admin: s(200, 400),
      anonymous: 401,
      disabled: 401,
    },
  },

  // --- Admin ---
  {
    method: 'GET',
    pathTemplate: '/api/admin/users',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'POST',
    pathTemplate: '/api/admin/users',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: s(200, 201, 400),
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'PATCH',
    pathTemplate: '/api/admin/users/:id',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: s(200, 400),
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'GET',
    pathTemplate: '/api/admin/audit',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'GET',
    pathTemplate: '/api/admin/audit/verify',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'POST',
    pathTemplate: '/api/admin/audit/verify',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'GET',
    pathTemplate: '/api/admin/audit/checkpoint/export',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },
  {
    method: 'GET',
    pathTemplate: '/api/admin/alerts',
    kind: 'admin',
    expected: {
      ownerA: 403,
      ownerB: 403,
      viewer: 403,
      admin: 200,
      anonymous: 401,
      disabled: 401,
    },
  },

  // --- Public operational ---
  {
    method: 'GET',
    pathTemplate: '/api/health',
    kind: 'public',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 200,
      disabled: 200,
    },
    forbidDocMetaLeak: true,
  },
  {
    method: 'GET',
    pathTemplate: '/api/openapi',
    kind: 'public',
    expected: {
      ownerA: 200,
      ownerB: 200,
      viewer: 200,
      admin: 200,
      anonymous: 200,
      disabled: 200,
    },
    forbidDocMetaLeak: true,
  },
];

export function inventoryKeys(entries: RouteInventoryEntry[] = ROUTE_INVENTORY): string[] {
  return entries.map((e) => `${e.method} ${e.pathTemplate}`).sort();
}

export function statusMatches(actual: number, expected: StatusExpectation): boolean {
  if (Array.isArray(expected)) return expected.includes(actual);
  return actual === expected;
}
