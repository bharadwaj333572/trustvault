import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import crypto from 'crypto';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { hashPassword } from '@/server/auth/password';
import { createSession, revokeAllUserSessions } from '@/server/auth/session';
import {
  discoverAppRoutes,
  discoverServerActions,
  flattenRouteKeys,
} from '@/server/security/discover-routes';
import {
  ROUTE_INVENTORY,
  inventoryKeys,
  statusMatches,
  type InventoryActor,
  type RouteInventoryEntry,
} from '@/server/security/route-inventory';
import { loginSeedActors, mintSeedActorTokens, originHeaders, authHeader, ensureViewerEnabled } from '../helpers/auth';
import { resetIpRateLimitStoreForTests } from '@/server/auth/rate-limit';

import { POST as loginHandler } from '@/app/api/auth/login/route';
import { POST as logoutHandler } from '@/app/api/auth/logout/route';
import { GET as meHandler } from '@/app/api/auth/me/route';
import { GET as sessionsGet, DELETE as sessionsDelete } from '@/app/api/auth/sessions/route';
import { POST as passwordHandler } from '@/app/api/auth/password/route';
import { GET as docsGet, POST as docsPost } from '@/app/api/documents/route';
import { POST as bulkHandler } from '@/app/api/documents/bulk/route';
import { GET as docGet, PATCH as docPatch, DELETE as docDelete } from '@/app/api/documents/[id]/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { POST as restoreHandler } from '@/app/api/documents/[id]/restore/route';
import { GET as activityHandler } from '@/app/api/documents/[id]/activity/route';
import { GET as grantsGet, POST as grantsPost } from '@/app/api/documents/[id]/grants/route';
import { DELETE as grantDelete } from '@/app/api/documents/[id]/grants/[grantId]/route';
import { GET as versionsGet, POST as versionsPost } from '@/app/api/documents/[id]/versions/route';
import { POST as versionRestoreHandler } from '@/app/api/documents/[id]/versions/[versionId]/restore/route';
import { GET as searchHandler } from '@/app/api/search/route';
import { GET as suggestionsHandler } from '@/app/api/suggestions/route';
import { POST as suggestionsFeedback } from '@/app/api/suggestions/feedback/route';
import { GET as autocompleteHandler } from '@/app/api/users/autocomplete/route';
import { GET as adminUsersGet, POST as adminUsersPost } from '@/app/api/admin/users/route';
import { PATCH as adminUserPatch } from '@/app/api/admin/users/[id]/route';
import { GET as adminAuditGet } from '@/app/api/admin/audit/route';
import { GET as adminVerifyGet, POST as adminVerifyPost } from '@/app/api/admin/audit/verify/route';
import { GET as checkpointExport } from '@/app/api/admin/audit/checkpoint/export/route';
import { GET as alertsHandler } from '@/app/api/admin/alerts/route';
import { GET as healthHandler } from '@/app/api/health/route';
import { GET as openapiHandler } from '@/app/api/openapi/route';

type Handler = (req: NextRequest, ctx?: any) => Promise<Response>;

const HANDLERS: Record<string, Handler> = {
  'POST /api/auth/login': loginHandler,
  'POST /api/auth/logout': logoutHandler,
  'GET /api/auth/me': meHandler,
  'GET /api/auth/sessions': sessionsGet,
  'DELETE /api/auth/sessions': sessionsDelete,
  'POST /api/auth/password': passwordHandler,
  'GET /api/documents': docsGet,
  'POST /api/documents': docsPost,
  'POST /api/documents/bulk': bulkHandler,
  'GET /api/documents/:id': docGet,
  'PATCH /api/documents/:id': docPatch,
  'DELETE /api/documents/:id': docDelete,
  'GET /api/documents/:id/download': downloadHandler,
  'POST /api/documents/:id/restore': restoreHandler,
  'GET /api/documents/:id/activity': activityHandler,
  'GET /api/documents/:id/grants': grantsGet,
  'POST /api/documents/:id/grants': grantsPost,
  'DELETE /api/documents/:id/grants/:grantId': grantDelete,
  'GET /api/documents/:id/versions': versionsGet,
  'POST /api/documents/:id/versions': versionsPost,
  'POST /api/documents/:id/versions/:versionId/restore': versionRestoreHandler,
  'GET /api/search': searchHandler,
  'GET /api/suggestions': suggestionsHandler,
  'POST /api/suggestions/feedback': suggestionsFeedback,
  'GET /api/users/autocomplete': autocompleteHandler,
  'GET /api/admin/users': adminUsersGet,
  'POST /api/admin/users': adminUsersPost,
  'PATCH /api/admin/users/:id': adminUserPatch,
  'GET /api/admin/audit': adminAuditGet,
  'GET /api/admin/audit/verify': adminVerifyGet,
  'POST /api/admin/audit/verify': adminVerifyPost,
  'GET /api/admin/audit/checkpoint/export': checkpointExport,
  'GET /api/admin/alerts': alertsHandler,
  'GET /api/health': healthHandler,
  'GET /api/openapi': openapiHandler,
};

const OWNER_A_TITLE = 'Route Inventory Owner A Secret Doc';
const SENSITIVE_MARKERS = [OWNER_A_TITLE, 'alice.owner@meridian.test'];

describe('Priority 1: Route inventory completeness and actor matrix', () => {
  let tokens: Record<'admin' | 'ownerA' | 'ownerB' | 'viewer', string>;
  let disabledToken: string;
  let ownerADocId: string;
  let ownerAVersionId: string;
  let ownerAGrantId: string;
  let disposableDocIds: string[] = [];
  let disabledUserId: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();
    await ensureViewerEnabled();
    tokens = await loginSeedActors();

    // Dedicated disabled user (does not disturb seed viewer)
    disabledUserId = crypto.randomUUID();
    await db.insert(schema.users).values({
      id: disabledUserId,
      email: 'disabled.probe@trustvault.test',
      fullName: 'Disabled Probe User',
      passwordHash: await hashPassword('DisabledPassword123!'),
      role: 'VIEWER',
      isDisabled: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    const { rawToken } = await createSession(disabledUserId, '127.0.0.1', 'inventory-disabled');
    await db
      .update(schema.users)
      .set({ isDisabled: true, updatedAt: new Date() })
      .where(eq(schema.users.id, disabledUserId));
    await revokeAllUserSessions(disabledUserId);
    disabledToken = rawToken;

    // Owner A private document
    const pdf = Buffer.from('%PDF-1.4\nRoute Inventory Owner A Secret Doc payload\n%%EOF');
    const form = new FormData();
    form.append('file', new Blob([pdf], { type: 'application/pdf' }), 'inventory_secret.pdf');
    form.append('title', OWNER_A_TITLE);
    form.append('category', 'CONFIDENTIAL');

    const uploadRes = await docsPost(
      new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { ...authHeader(tokens.ownerA), ...originHeaders() },
        body: form,
      })
    );
    expect(uploadRes.status).toBeLessThan(300);
    const uploadJson = await uploadRes.json();
    ownerADocId = uploadJson.document.id;

    const versionsRes = await versionsGet(
      new NextRequest(`http://localhost:3000/api/documents/${ownerADocId}/versions`, {
        headers: { ...authHeader(tokens.ownerA) },
      }),
      { params: { id: ownerADocId } }
    );
    const versionsJson = await versionsRes.json();
    ownerAVersionId = versionsJson.versions?.[0]?.id || versionsJson[0]?.id;

    // Placeholder grant id (may 404 on delete — expected)
    ownerAGrantId = '00000000-0000-0000-0000-000000000099';
  }, 60000);

  afterAll(async () => {
    await ensureViewerEnabled();
  });

  it('fails if any discovered route/method is missing from the inventory', () => {
    const discovered = flattenRouteKeys(discoverAppRoutes());
    const inventoried = inventoryKeys();

    const missingFromInventory = discovered.filter((k) => !inventoried.includes(k));
    const orphanInventory = inventoried.filter((k) => !discovered.includes(k));

    expect(missingFromInventory, `Uninventoried routes: ${missingFromInventory.join(', ')}`).toEqual([]);
    expect(orphanInventory, `Inventory orphans (no route file): ${orphanInventory.join(', ')}`).toEqual([]);
  });

  it('fails if a handler key is missing for an inventory entry', () => {
    for (const key of inventoryKeys()) {
      expect(HANDLERS[key], `No test handler wired for ${key}`).toBeTypeOf('function');
    }
  });

  it('lists every server action; suite fails if an untracked "use server" module appears', () => {
    const actions = discoverServerActions();
    // TrustVault currently has no server actions — all mutations go through inventoried API routes.
    // If a "use server" module is added, it MUST be added to this allowlist after a full actor matrix.
    const ALLOWED_SERVER_ACTION_FILES: string[] = [];
    const unexpected = actions.filter((a) => !ALLOWED_SERVER_ACTION_FILES.includes(a.file));
    expect(unexpected, `Untracked server actions: ${JSON.stringify(unexpected)}`).toEqual([]);
  });

  it('exercises every inventoried route as Owner B, Viewer, Admin, anonymous, and disabled against Owner A document', async () => {
    const actors: InventoryActor[] = ['ownerA', 'ownerB', 'viewer', 'admin', 'anonymous', 'disabled'];
    const failures: string[] = [];

    for (const entry of ROUTE_INVENTORY) {
      for (const actor of actors) {
        try {
          const { status, bodyText } = await invokeEntry(entry, actor);
          if (!statusMatches(status, entry.expected[actor])) {
            failures.push(
              `${entry.method} ${entry.pathTemplate} as ${actor}: got ${status}, expected ${JSON.stringify(entry.expected[actor])}`
            );
          }

          const unauthorized =
            actor === 'ownerB' ||
            actor === 'viewer' ||
            actor === 'admin' ||
            actor === 'anonymous' ||
            actor === 'disabled';

          if (entry.forbidDocMetaLeak && unauthorized && bodyText) {
            for (const marker of SENSITIVE_MARKERS) {
              // Owner A email may appear in admin user lists — only enforce on document-scoped leaks
              if (entry.kind === 'admin' && marker.includes('@')) continue;
              if (entry.kind === 'public') {
                if (bodyText.includes(OWNER_A_TITLE)) {
                  failures.push(`${entry.method} ${entry.pathTemplate} as ${actor}: leaked document title`);
                }
                continue;
              }
              if (entry.kind === 'collection' || entry.kind === 'document') {
                if (bodyText.includes(OWNER_A_TITLE)) {
                  failures.push(
                    `${entry.method} ${entry.pathTemplate} as ${actor}: leaked Owner A title in body`
                  );
                }
              }
            }
          }
        } catch (err: any) {
          failures.push(`${entry.method} ${entry.pathTemplate} as ${actor}: threw ${err.message}`);
        }
      }

      // Session-mutating probes (even with ephemeral tokens) may delete sibling sessions.
      if (
        (entry.pathTemplate === '/api/auth/sessions' && entry.method === 'DELETE') ||
        entry.pathTemplate === '/api/auth/password' ||
        entry.pathTemplate === '/api/auth/login'
      ) {
        resetIpRateLimitStoreForTests();
        tokens = await mintSeedActorTokens();
      }
    }

    expect(failures, failures.join('\n')).toEqual([]);
  }, 120000);

  async function tokenFor(actor: InventoryActor): Promise<string | null> {
    if (actor === 'anonymous') return null;
    if (actor === 'disabled') return disabledToken;
    return tokens[actor];
  }

  /** Mint a throwaway session so logout/password probes never revoke fixture tokens. */
  async function ephemeralTokenFor(actor: InventoryActor): Promise<string | null> {
    if (actor === 'anonymous' || actor === 'disabled') return tokenFor(actor);
    const email =
      actor === 'ownerA'
        ? SEED_CREDENTIALS.owner1.email
        : actor === 'ownerB'
          ? SEED_CREDENTIALS.owner2.email
          : actor === 'viewer'
            ? SEED_CREDENTIALS.viewer.email
            : SEED_CREDENTIALS.admin.email;
    const users = await db.select().from(schema.users).where(eq(schema.users.email, email)).limit(1);
    const { rawToken } = await createSession(users[0]!.id, '127.0.0.1', 'inventory-ephemeral');
    return rawToken;
  }

  async function invokeEntry(
    entry: RouteInventoryEntry,
    actor: InventoryActor
  ): Promise<{ status: number; bodyText: string }> {
    const key = `${entry.method} ${entry.pathTemplate}`;
    const handler = HANDLERS[key];

    const mutatesOwnSession =
      entry.pathTemplate === '/api/auth/logout' ||
      entry.pathTemplate === '/api/auth/password' ||
      (entry.pathTemplate === '/api/auth/sessions' && entry.method === 'DELETE');

    const token = mutatesOwnSession ? await ephemeralTokenFor(actor) : await tokenFor(actor);

    // Destructive ownerA mutations use disposable docs so the matrix fixture survives
    let docId = ownerADocId;
    let versionId = ownerAVersionId;
    if (
      actor === 'ownerA' &&
      (entry.pathTemplate === '/api/documents/:id' && (entry.method === 'DELETE' || entry.method === 'PATCH'))
    ) {
      docId = await createDisposableDoc(tokens.ownerA);
    }
    if (actor === 'ownerA' && entry.pathTemplate.includes('/versions/:versionId/restore')) {
      const created = await createDisposableDocWithVersion(tokens.ownerA);
      docId = created.docId;
      versionId = created.versionId;
    }

    const url = buildUrl(entry, docId, versionId, actor);
    const headers: Record<string, string> = {
      ...originHeaders(),
      ...authHeader(token),
    };

    let body: BodyInit | undefined;
    if (entry.method === 'POST' || entry.method === 'PATCH' || entry.method === 'PUT') {
      if (entry.pathTemplate === '/api/auth/login') {
        headers['content-type'] = 'application/json';
        if (actor === 'anonymous') {
          body = JSON.stringify({ email: 'nobody@example.com', password: 'wrong' });
        } else if (actor === 'disabled') {
          body = JSON.stringify({
            email: 'disabled.probe@trustvault.test',
            password: 'DisabledPassword123!',
          });
        } else {
          const cred =
            actor === 'ownerA'
              ? SEED_CREDENTIALS.owner1
              : actor === 'ownerB'
                ? SEED_CREDENTIALS.owner2
                : actor === 'viewer'
                  ? SEED_CREDENTIALS.viewer
                  : SEED_CREDENTIALS.admin;
          body = JSON.stringify({ email: cred.email, password: cred.password });
        }
      } else if (entry.pathTemplate === '/api/documents' && entry.method === 'POST') {
        // Empty multipart (no file) → 400 for upload-capable roles; viewer blocked at role check
        body = new FormData();
      } else if (entry.pathTemplate === '/api/documents/bulk') {
        headers['content-type'] = 'application/json';
        // Never destroy the shared Owner A fixture — probe a non-existent id (skipped)
        body = JSON.stringify({
          action: 'delete',
          documentIds: ['00000000-0000-0000-0000-0000000000aa'],
        });
      } else if (entry.pathTemplate === '/api/documents/:id' && entry.method === 'PATCH') {
        headers['content-type'] = 'application/json';
        body = JSON.stringify({ title: 'Inventory Patch Title' });
      } else if (entry.pathTemplate === '/api/documents/:id/grants' && entry.method === 'POST') {
        headers['content-type'] = 'application/json';
        body = JSON.stringify({ targetEmail: 'nonexistent@example.com', permission: 'READ' });
      } else if (entry.pathTemplate === '/api/auth/password') {
        headers['content-type'] = 'application/json';
        body = JSON.stringify({});
      } else if (entry.pathTemplate === '/api/admin/users' && entry.method === 'POST') {
        headers['content-type'] = 'application/json';
        body = JSON.stringify({});
      } else if (entry.pathTemplate === '/api/admin/users/:id') {
        headers['content-type'] = 'application/json';
        body = JSON.stringify({});
      } else if (entry.pathTemplate === '/api/suggestions/feedback') {
        headers['content-type'] = 'application/json';
        body = JSON.stringify({});
      } else if (entry.pathTemplate.endsWith('/versions') && entry.method === 'POST') {
        body = new FormData();
      } else {
        headers['content-type'] = 'application/json';
        body = JSON.stringify({});
      }
    }

    const req = new NextRequest(url, { method: entry.method, headers, body });
    const params = extractParams(entry.pathTemplate, docId, versionId);
    const res = await handler(req, { params });
    const bodyText = await res.text();
    return { status: res.status, bodyText };
  }

  function buildUrl(
    entry: RouteInventoryEntry,
    docId: string,
    versionId: string,
    actor: InventoryActor
  ): string {
    let p = entry.pathTemplate
      .replace(':id', docId)
      .replace(':grantId', ownerAGrantId)
      .replace(':versionId', versionId || '00000000-0000-0000-0000-000000000001');

    if (entry.pathTemplate === '/api/admin/users/:id') {
      p = `/api/admin/users/${disabledUserId}`;
    }
    if (entry.pathTemplate === '/api/suggestions') {
      return `http://localhost:3000/api/suggestions?documentId=${docId}`;
    }
    if (entry.pathTemplate === '/api/users/autocomplete') {
      return `http://localhost:3000/api/users/autocomplete?q=ali`;
    }
    if (entry.pathTemplate === '/api/search') {
      return `http://localhost:3000/api/search?q=${encodeURIComponent(OWNER_A_TITLE)}`;
    }
    void actor;
    return `http://localhost:3000${p}`;
  }

  function extractParams(template: string, docId: string, versionId: string): Record<string, string> {
    const params: Record<string, string> = {};
    if (template.includes(':id')) params.id = docId;
    if (template.includes(':grantId')) params.grantId = ownerAGrantId;
    if (template.includes(':versionId')) params.versionId = versionId || '00000000-0000-0000-0000-000000000001';
    if (template === '/api/admin/users/:id') params.id = disabledUserId;
    return params;
  }

  async function createDisposableDoc(ownerToken: string): Promise<string> {
    const pdf = Buffer.from('%PDF-1.4\nDisposable inventory doc\n%%EOF');
    const form = new FormData();
    form.append('file', new Blob([pdf], { type: 'application/pdf' }), 'disposable.pdf');
    form.append('title', 'Disposable Inventory Doc');
    const res = await docsPost(
      new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { ...authHeader(ownerToken), ...originHeaders() },
        body: form,
      })
    );
    const json = await res.json();
    disposableDocIds.push(json.document.id);
    return json.document.id;
  }

  async function createDisposableDocWithVersion(
    ownerToken: string
  ): Promise<{ docId: string; versionId: string }> {
    const docId = await createDisposableDoc(ownerToken);
    const versionsRes = await versionsGet(
      new NextRequest(`http://localhost:3000/api/documents/${docId}/versions`, {
        headers: { ...authHeader(ownerToken) },
      }),
      { params: { id: docId } }
    );
    const json = await versionsRes.json();
    const versionId = json.versions?.[0]?.id || json[0]?.id;
    return { docId, versionId };
  }
});

describe('Priority 1: Edge path non-disclosure', () => {
  let tokens: Record<'admin' | 'ownerA' | 'ownerB' | 'viewer', string>;
  let secretDocId: string;
  const SECRET_TITLE = 'Edge Path Non Disclosure Secret';

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();
    resetIpRateLimitStoreForTests();
    tokens = await mintSeedActorTokens();

    const pdf = Buffer.from('%PDF-1.4\nEdge Path Non Disclosure Secret\n%%EOF');
    const form = new FormData();
    form.append('file', new Blob([pdf], { type: 'application/pdf' }), 'edge_secret.pdf');
    form.append('title', SECRET_TITLE);
    const uploadRes = await docsPost(
      new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { ...authHeader(tokens.ownerA), ...originHeaders() },
        body: form,
      })
    );
    secretDocId = (await uploadRes.json()).document.id;
  }, 60000);

  it('health endpoint reveals version/migration status but never document metadata', async () => {
    const res = await healthHandler();
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.version).toBeTruthy();
    expect(json.migrationStatus).toMatch(/ok|degraded/);
    expect(JSON.stringify(json)).not.toContain(SECRET_TITLE);
    expect(json).not.toHaveProperty('documents');
    expect(json).not.toHaveProperty('documentCount');
  });

  it('OpenAPI endpoint does not embed live document titles or owners', async () => {
    const res = await openapiHandler();
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toMatch(/openapi:/i);
    expect(text).not.toContain(SECRET_TITLE);
    expect(text).not.toContain(secretDocId);
  });

  it('search facets/counts never include ungranted Owner A documents for Owner B', async () => {
    const res = await searchHandler(
      new NextRequest(
        `http://localhost:3000/api/search?q=${encodeURIComponent(SECRET_TITLE)}`,
        { headers: { ...authHeader(tokens.ownerB) } }
      )
    );
    expect(res.status).toBe(200);
    const json = await res.json();
    const serialized = JSON.stringify(json);
    expect(serialized).not.toContain(SECRET_TITLE);
    expect(serialized).not.toContain(secretDocId);
    expect(json.pagination?.total ?? json.items?.length ?? 0).toBe(0);
  });

  it('range request on ungranted document returns uniform 404 without Content-Range size leak', async () => {
    const res = await downloadHandler(
      new NextRequest(`http://localhost:3000/api/documents/${secretDocId}/download`, {
        headers: {
          ...authHeader(tokens.ownerB),
          Range: 'bytes=0-100',
        },
      }),
      { params: { id: secretDocId } }
    );
    expect(res.status).toBe(404);
    expect(res.headers.get('content-range')).toBeNull();
    const json = await res.json();
    expect(json.error.code).toBe('NOT_FOUND');
  });

  it('activity and share endpoints do not disclose ungranted documents', async () => {
    const activity = await activityHandler(
      new NextRequest(`http://localhost:3000/api/documents/${secretDocId}/activity`, {
        headers: { ...authHeader(tokens.viewer) },
      }),
      { params: { id: secretDocId } }
    );
    expect(activity.status).toBe(404);

    const grants = await grantsGet(
      new NextRequest(`http://localhost:3000/api/documents/${secretDocId}/grants`, {
        headers: { ...authHeader(tokens.admin) },
      }),
      { params: { id: secretDocId } }
    );
    expect(grants.status).toBe(404);
  });
});
