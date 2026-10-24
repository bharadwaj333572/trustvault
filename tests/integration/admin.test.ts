import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { GET as getAuditHandler } from '@/app/api/admin/audit/route';
import { GET as getVerifyHandler } from '@/app/api/admin/audit/verify/route';
import { GET as getAlertsHandler } from '@/app/api/admin/alerts/route';
import { GET as getUsersHandler } from '@/app/api/admin/users/route';
import { PATCH as patchUserHandler } from '@/app/api/admin/users/[id]/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME, validateSession } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';

describe('Admin Capabilities & Boundary Isolation Integration', () => {
  let adminToken: string;
  let ownerToken: string;
  let viewerToken: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    // Authenticate Admin
    const adminRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.admin.email, password: SEED_CREDENTIALS.admin.password }),
      })
    );
    adminToken = adminRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Authenticate Owner
    const ownerRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    ownerToken = ownerRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Authenticate Viewer
    const viewerRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    viewerToken = viewerRes.cookies.get(SESSION_COOKIE_NAME)!.value;
  });

  it('strictly forbids non-admin users from accessing admin audit endpoint (403)', async () => {
    const req = new NextRequest('http://localhost:3000/api/admin/audit', {
      method: 'GET',
      headers: { authorization: `Bearer ${ownerToken}` },
    });
    const res = await getAuditHandler(req);
    expect(res.status).toBe(403);
  });

  it('allows Admin to query global audit logs and download CSV export', async () => {
    // 1. JSON pagination query
    const reqJson = new NextRequest('http://localhost:3000/api/admin/audit?limit=10', {
      method: 'GET',
      headers: { authorization: `Bearer ${adminToken}` },
    });
    const resJson = await getAuditHandler(reqJson);
    expect(resJson.status).toBe(200);
    const json = await resJson.json();
    expect(json.logs.length).toBeGreaterThan(0);
    expect(json.pagination.total).toBeGreaterThan(0);

    // 2. CSV Export
    const reqCsv = new NextRequest('http://localhost:3000/api/admin/audit?format=csv', {
      method: 'GET',
      headers: { authorization: `Bearer ${adminToken}` },
    });
    const resCsv = await getAuditHandler(reqCsv);
    expect(resCsv.status).toBe(200);
    expect(resCsv.headers.get('content-type')).toContain('text/csv');
    const csvContent = await resCsv.text();
    expect(csvContent).toContain('sequence_number,timestamp,action,outcome');
  });

  it('allows Admin to verify cryptographic hash chain and returns status badge', async () => {
    const req = new NextRequest('http://localhost:3000/api/admin/audit/verify', {
      method: 'GET',
      headers: { authorization: `Bearer ${adminToken}` },
    });
    const res = await getVerifyHandler(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.valid).toBe(true);
    expect(json.badge).toBe('CHAIN VERIFIED');
  });

  it('allows Admin to evaluate automated security alerts', async () => {
    const req = new NextRequest('http://localhost:3000/api/admin/alerts', {
      method: 'GET',
      headers: { authorization: `Bearer ${adminToken}` },
    });
    const res = await getAlertsHandler(req);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(Array.isArray(json.alerts)).toBe(true);
  });

  it('allows Admin to disable a user, immediately terminating all active sessions', async () => {
    const targetUser = await db.select().from(schema.users).where(eq(schema.users.email, SEED_CREDENTIALS.viewer.email));
    const targetId = targetUser[0].id;

    // Admin disables user
    const patchReq = new NextRequest(`http://localhost:3000/api/admin/users/${targetId}`, {
      method: 'PATCH',
      headers: { authorization: `Bearer ${adminToken}`, 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
      body: JSON.stringify({ isDisabled: true }),
    });

    const patchRes = await patchUserHandler(patchReq, { params: { id: targetId } });
    expect(patchRes.status).toBe(200);

    // Verify session was immediately destroyed
    await expect(validateSession(viewerToken)).rejects.toThrow();
  });

  it('CRUCIAL: Admin CANNOT read or download document contents unless explicitly granted', async () => {
    const seedDocs = await db.select().from(schema.documents).where(eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'));
    const docId = seedDocs[0].id;

    const req = new NextRequest(`http://localhost:3000/api/documents/${docId}/download`, {
      method: 'GET',
      headers: { authorization: `Bearer ${adminToken}` },
    });

    const res = await downloadHandler(req, { params: { id: docId } });
    expect(res.status).toBe(404);
    const json = await res.json();
    expect(json.error.code).toBe('NOT_FOUND');
  });
});
