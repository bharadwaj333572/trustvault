import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { GET as getDocumentsHandler, POST as postDocumentHandler } from '@/app/api/documents/route';
import { GET as getSingleDocHandler, DELETE as deleteDocHandler } from '@/app/api/documents/[id]/route';
import { GET as downloadHandler } from '@/app/api/documents/[id]/download/route';
import { GET as searchHandler } from '@/app/api/search/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { detectMagicBytes, sanitizeFileName } from '@/server/validation/upload';

describe('Documents & Upload Security Integration', () => {
  let aliceToken: string;
  let bobToken: string;
  let carolToken: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    // Login Alice (Owner 1)
    const aliceRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    aliceToken = aliceRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Login Bob (Owner 2)
    const bobRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner2.email, password: SEED_CREDENTIALS.owner2.password }),
      })
    );
    bobToken = bobRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Login Carol (Viewer)
    const carolRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    carolToken = carolRes.cookies.get(SESSION_COOKIE_NAME)!.value;
  });

  describe('1. Upload Validation & Magic Byte Sniffing', () => {
    it('accepts genuine PDF magic bytes (%PDF)', () => {
      const pdfBuffer = Buffer.from('%PDF-1.7\nValid pdf mock payload\n%%EOF');
      const detected = detectMagicBytes(pdfBuffer);
      expect(detected).toBe('application/pdf');
    });

    it('rejects an executable disguised with a .pdf extension (MZ header)', () => {
      const fakePdfExecutable = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00');
      expect(() => detectMagicBytes(fakePdfExecutable)).toThrow(/Executable PE binaries/);
    });

    it('rejects an HTML file disguised as a document (stored XSS prevention)', () => {
      const fakePdfHtml = Buffer.from('<html><script>alert(1)</script></html>');
      expect(() => detectMagicBytes(fakePdfHtml)).toThrow(/HTML, SVG, and shell scripts cannot be uploaded/);
    });

    it('sanitizes path traversal and control characters from filenames', () => {
      const dangerousName = '../../../../etc/passwd\x00.pdf';
      const clean = sanitizeFileName(dangerousName);
      expect(clean).not.toContain('..');
      expect(clean).not.toContain('/');
      expect(clean).not.toContain('\x00');
    });
  });

  describe('2. Document Isolation: User A vs User B', () => {
    let aliceDocId: string;

    it('allows Alice to upload a genuine document', async () => {
      const pdfBytes = Buffer.from('%PDF-1.4\nConfidential Alice Contract 2026\n%%EOF');
      const formData = new FormData();
      formData.append('file', new Blob([pdfBytes], { type: 'application/pdf' }), 'contract.pdf');
      formData.append('title', 'Alice Secret Q4 NDA');
      formData.append('category', 'LEGAL');
      formData.append('ownerId', 'injected_rogue_id'); // Mass assignment probe

      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${aliceToken}`,
          origin: 'http://localhost:3000',
          host: 'localhost:3000',
        },
        body: formData,
      });

      const res = await postDocumentHandler(req);
      expect(res.status).toBe(201);
      const json = await res.json();
      expect(json.success).toBe(true);
      expect(json.document.title).toBe('Alice Secret Q4 NDA');
      aliceDocId = json.document.id;
    });

    it('strictly forbids Bob from reading Alices document via direct ID (returns 404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${bobToken}` },
      });

      const res = await getSingleDocHandler(req, { params: { id: aliceDocId } });
      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });

    it('strictly forbids Bob from downloading Alices document (returns 404)', async () => {
      const req = new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/download`, {
        method: 'GET',
        headers: { authorization: `Bearer ${bobToken}` },
      });

      const res = await downloadHandler(req, { params: { id: aliceDocId } });
      expect(res.status).toBe(404);
      const json = await res.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });

    it('does NOT leak Alices document to Bob in list or search queries', async () => {
      // Bob searches for "Alice Secret Q4 NDA"
      const req = new NextRequest('http://localhost:3000/api/search?q=Alice', {
        method: 'GET',
        headers: { authorization: `Bearer ${bobToken}` },
      });

      const res = await searchHandler(req);
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.items.length).toBe(0);
      expect(json.pagination.total).toBe(0);
    });

    it('forbids Viewer (Carol) from uploading documents (403)', async () => {
      const pdfBytes = Buffer.from('%PDF-1.4\nViewer attempted upload\n%%EOF');
      const formData = new FormData();
      formData.append('file', new Blob([pdfBytes], { type: 'application/pdf' }), 'viewer_doc.pdf');
      formData.append('title', 'Illegal Viewer Upload');

      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${carolToken}`,
          origin: 'http://localhost:3000',
          host: 'localhost:3000',
        },
        body: formData,
      });

      const res = await postDocumentHandler(req);
      expect(res.status).toBe(403);
    });
  });

  describe('3. Soft-Delete and Trash Isolation', () => {
    let docToDeleteId: string;

    beforeAll(async () => {
      // Upload a doc to delete
      const pdfBytes = Buffer.from('%PDF-1.4\nDoc to be soft deleted\n%%EOF');
      const formData = new FormData();
      formData.append('file', new Blob([pdfBytes], { type: 'application/pdf' }), 'trash_me.pdf');
      formData.append('title', 'Temporary Alice Draft');

      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: formData,
      });
      const res = await postDocumentHandler(req);
      const json = await res.json();
      docToDeleteId = json.document.id;
    });

    it('allows owner to soft delete document', async () => {
      const req = new NextRequest(`http://localhost:3000/api/documents/${docToDeleteId}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${aliceToken}`, origin: 'http://localhost:3000', host: 'localhost:3000' },
      });

      const res = await deleteDocHandler(req, { params: { id: docToDeleteId } });
      expect(res.status).toBe(200);
    });

    it('renders soft-deleted document completely unreachable to non-owners', async () => {
      const req = new NextRequest(`http://localhost:3000/api/documents/${docToDeleteId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${bobToken}` },
      });

      const res = await getSingleDocHandler(req, { params: { id: docToDeleteId } });
      expect(res.status).toBe(404);
    });
  });
});
