import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { POST as postDocumentHandler } from '@/app/api/documents/route';
import { GET as getSingleDocHandler, PATCH as patchDocHandler, DELETE as deleteDocHandler } from '@/app/api/documents/[id]/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { POST as createGrantHandler } from '@/app/api/documents/[id]/grants/route';
import { GET as searchHandler } from '@/app/api/search/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq, desc } from 'drizzle-orm';
import { sanitizeFileName, validateUploadedFile } from '@/server/validation/upload';
import crypto from 'crypto';

describe('Phase 9: Adversarial Attack Pass & Threat Verification', () => {
  let adminToken: string;
  let aliceToken: string; // Owner 1
  let bobToken: string;   // Owner 2
  let carolToken: string; // Viewer

  let aliceDocId: string;
  let bobDocId: string;

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

    // Authenticate Alice (Owner 1)
    const aliceRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    aliceToken = aliceRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Authenticate Bob (Owner 2)
    const bobRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
      })
    );
    bobToken = bobRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Authenticate Carol (Viewer)
    const carolRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    carolToken = carolRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Alice uploads a confidential document
    const aliceFile = Buffer.from('%PDF-1.7\nAlice Highly Secret Quantum Algorithms\n%%EOF');
    const aliceForm = new FormData();
    aliceForm.append('file', new Blob([aliceFile], { type: 'application/pdf' }), 'quantum_secret.pdf');
    aliceForm.append('title', 'Alice Secret Quantum File');
    aliceForm.append('category', 'LEGAL');

    const aliceUploadRes = await postDocumentHandler(
      new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: aliceForm,
      })
    );
    const aliceUploadJson = await aliceUploadRes.json();
    aliceDocId = aliceUploadJson.document.id;

    // Bob uploads a document
    const bobFile = Buffer.from('%PDF-1.4\nBob Confidential Marketing Playbook\n%%EOF');
    const bobForm = new FormData();
    bobForm.append('file', new Blob([bobFile], { type: 'application/pdf' }), 'bob_playbook.pdf');
    bobForm.append('title', 'Bob Playbook');
    bobForm.append('category', 'OPERATIONS');

    const bobUploadRes = await postDocumentHandler(
      new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { authorization: `Bearer ${bobToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: bobForm,
      })
    );
    const bobUploadJson = await bobUploadRes.json();
    bobDocId = bobUploadJson.document.id;
  });

  describe('1. IDOR Defense (Insecure Direct Object Reference)', () => {
    it('Carol cannot view Alice confidential document by ID (returns 404 without existence leak)', async () => {
      const res = await getSingleDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });

    it('Bob cannot download Alice confidential document by ID (returns 404)', async () => {
      const res = await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download`, {
          headers: { authorization: `Bearer ${bobToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(404);
    });

    it('returns exact same 404 shape for non-existent doc ID vs unpermitted doc ID', async () => {
      const fakeDocId = '00000000-0000-0000-0000-000000000000';
      const fakeRes = await getSingleDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${fakeDocId}`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: fakeDocId } }
      );
      const fakeJson = await fakeRes.json();

      const realDocUnpermittedRes = await getSingleDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      const realDocJson = await realDocUnpermittedRes.json();

      expect(fakeRes.status).toBe(realDocUnpermittedRes.status);
      expect(fakeJson.error.code).toBe(realDocJson.error.code);
      expect(fakeJson.error.message).toBe(realDocJson.error.message);
    });
  });

  describe('2. Mass Assignment Defense', () => {
    it('ignores client-sent ownerId when creating a document', async () => {
      // Bob attempts to upload a file claiming Alice is the owner
      const pdfBytes = Buffer.from('%PDF-1.4\nAttempted Spoofed Ownership File\n%%EOF');
      const form = new FormData();
      form.append('file', new Blob([pdfBytes], { type: 'application/pdf' }), 'spoof.pdf');
      form.append('title', 'Spoofed Ownership Doc');
      form.append('ownerId', 'alice-fake-id');

      const res = await postDocumentHandler(
        new NextRequest('http://localhost:3000/api/documents', {
          method: 'POST',
          headers: { authorization: `Bearer ${bobToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: form,
        })
      );
      expect(res.status).toBe(201);
      const json = await res.json();
      // True owner MUST be Bob, regardless of what was submitted in the form
      const doc = await db.query.documents.findFirst({ where: eq(schema.documents.id, json.document.id) });
      const bobUser = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.owner2.email) });
      expect(doc?.ownerId).toBe(bobUser?.id);
    });

    it('ignores ownerId or isDeleted modifications during document PATCH', async () => {
      // Bob attempts to reassign Alice's document to himself via PATCH
      const patchRes = await patchDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          method: 'PATCH',
          headers: {
            authorization: `Bearer ${bobToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({
            title: 'Hacked Title',
            ownerId: 'attacker-id',
            isDeleted: true,
          }),
        }),
        { params: { id: aliceDocId } }
      );
      // Denied because Bob has no edit permission
      expect(patchRes.status).toBe(404);

      // Even if Alice patches her own doc, ownerId and isDeleted cannot be manipulated
      const alicePatchRes = await patchDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          method: 'PATCH',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({
            title: 'Legit Quantum Title Change',
            ownerId: 'transferred-id',
            isDeleted: true,
          }),
        }),
        { params: { id: aliceDocId } }
      );
      expect(alicePatchRes.status).toBe(200);

      const docInDb = await db.query.documents.findFirst({ where: eq(schema.documents.id, aliceDocId) });
      expect(docInDb?.title).toBe('Legit Quantum Title Change');
      expect(docInDb?.isDeleted).toBe(false); // isDeleted was ignored!
    });
  });

  describe('3. Search Query Cross-Tenant Leakage Prevention', () => {
    it('search queries filter strictly at SQL level and never leak other users documents', async () => {
      // Bob searches for "Quantum" (which is in Alice's document title)
      const res = await searchHandler(
        new NextRequest('http://localhost:3000/api/search?q=Quantum', {
          headers: { authorization: `Bearer ${bobToken}` },
        })
      );
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.items.length).toBe(0);
      expect(json.pagination.total).toBe(0);
    });

    it('Alice searching for "Quantum" returns her document', async () => {
      const res = await searchHandler(
        new NextRequest('http://localhost:3000/api/search?q=Quantum', {
          headers: { authorization: `Bearer ${aliceToken}` },
        })
      );
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.items.length).toBe(1);
      expect(json.items[0].id).toBe(aliceDocId);
    });
  });

  describe('4. Privilege Escalation & Role Boundaries', () => {
    it('VIEWER role cannot upload documents (fails with 403 Forbidden)', async () => {
      const pdfBytes = Buffer.from('%PDF-1.4\nViewer Attempting Upload\n%%EOF');
      const form = new FormData();
      form.append('file', new Blob([pdfBytes], { type: 'application/pdf' }), 'viewer_upload.pdf');
      form.append('title', 'Illegal Viewer Upload');

      const res = await postDocumentHandler(
        new NextRequest('http://localhost:3000/api/documents', {
          method: 'POST',
          headers: { authorization: `Bearer ${carolToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
          body: form,
        })
      );
      expect(res.status).toBe(403);
      const json = await res.json();
      expect(json.error.code).toBe('UNAUTHORIZED');
    });

    it('Granted user (READ) cannot share/grant document to someone else', async () => {
      // Grant Carol READ on Alice's doc
      await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${aliceToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: SEED_CREDENTIALS.viewer.email, permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );

      // Now Carol tries to grant access to Bob
      const unauthorizedGrantRes = await createGrantHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: {
            authorization: `Bearer ${carolToken}`,
            'content-type': 'application/json',
            origin: 'http://localhost:3000',
            host: 'localhost:3000',
          },
          body: JSON.stringify({ targetEmail: SEED_CREDENTIALS.owner2.email, permission: 'READ' }),
        }),
        { params: { id: aliceDocId } }
      );

      // Returns 404 (non-owner cannot manage grants)
      expect(unauthorizedGrantRes.status).toBe(404);
    });

    it('Granted user cannot delete document (only OWNER has delete privilege)', async () => {
      const deleteRes = await deleteDocHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
          method: 'DELETE',
          headers: { authorization: `Bearer ${carolToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        }),
        { params: { id: aliceDocId } }
      );
      expect(deleteRes.status).toBe(404);
    });

    it('ADMIN role CANNOT download document contents without explicit grant (Admin content isolation)', async () => {
      const res = await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download`, {
          headers: { authorization: `Bearer ${adminToken}` },
        }),
        { params: { id: aliceDocId } }
      );
      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });
  });

  describe('5. Audit Trail Completeness & Denied Logging', () => {
    it('records a DENIED audit log entry whenever access is denied', async () => {
      // Bob attempts to download Alice's document
      await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download`, {
          headers: { authorization: `Bearer ${bobToken}` },
        }),
        { params: { id: aliceDocId } }
      );

      // Fetch latest audit logs
      const bobUser = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.owner2.email) });
      const latestDeniedLog = await db.query.auditLogs.findFirst({
        where: eq(schema.auditLogs.actorId, bobUser!.id),
        orderBy: [desc(schema.auditLogs.sequenceNumber)],
      });

      expect(latestDeniedLog).toBeDefined();
      expect(latestDeniedLog?.outcome).toBe('DENIED');
      expect(latestDeniedLog?.action).toBe('DENIED_ATTEMPT');
      expect(latestDeniedLog?.documentId).toBe(aliceDocId);
    });
  });

  describe('6. Grant Expiry Enforcement', () => {
    it('immediately denies access once a grant has expired', async () => {
      const carolUser = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.viewer.email) });
      const bobUser = await db.query.users.findFirst({ where: eq(schema.users.email, SEED_CREDENTIALS.owner2.email) });
      
      // Create an expired grant on Bob's document
      const pastDate = new Date(Date.now() - 3600 * 1000); // 1 hour ago
      await db.insert(schema.documentGrants).values({
        id: crypto.randomUUID(),
        documentId: bobDocId,
        userId: carolUser!.id,
        permission: 'READ',
        grantedBy: bobUser!.id,
        expiresAt: pastDate,
        createdAt: pastDate,
      });

      // Carol attempts to download Bob's document
      const res = await downloadHandler(
        new NextRequest(`http://localhost:3000/api/documents/${bobDocId}/download`, {
          headers: { authorization: `Bearer ${carolToken}` },
        }),
        { params: { id: bobDocId } }
      );

      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });
  });

  describe('7. Upload Validation & Polyglot Defense', () => {
    it('rejects zero-byte empty files', () => {
      const emptyBuffer = Buffer.alloc(0);
      expect(() => validateUploadedFile(emptyBuffer, 'empty.pdf')).toThrow(/File cannot be empty/);
    });

    it('rejects executable disguised with valid PDF extension', () => {
      const exeBuffer = Buffer.from('MZ\x90\x00ThisIsAnExecutableFile.exe');
      expect(() => validateUploadedFile(exeBuffer, 'dangerous.pdf')).toThrow(/Executable PE binaries/);
    });

    it('rejects HTML/SVG payload masquerading as docx', () => {
      const htmlBuffer = Buffer.from('<!DOCTYPE html><html><body><script>alert(document.cookie)</script></body></html>');
      expect(() => validateUploadedFile(htmlBuffer, 'exploit.docx')).toThrow(/HTML, SVG, and shell scripts cannot be uploaded/);
    });

    it('strips directory traversal attempts from filename', () => {
      const cleaned = sanitizeFileName('../../../../windows/system32/cmd.exe.pdf');
      expect(cleaned).not.toContain('..');
      expect(cleaned).not.toContain('/');
      expect(cleaned).not.toContain('\\');
    });
  });
});
