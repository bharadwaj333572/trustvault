import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { POST as uploadHandler, GET as listDocsHandler } from '@/app/api/documents/route';
import { POST as grantHandler } from '@/app/api/documents/[id]/grants/route';
import { GET as autocompleteHandler } from '@/app/api/users/autocomplete/route';
import { middleware } from '@/middleware';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { resetIpRateLimitStoreForTests } from '@/server/auth/rate-limit';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';

describe('Headers, CSRF Defense, Polyglot Rejection, and Rate Limiting', () => {
  let aliceToken: string;
  let aliceDocId: string;

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    const aliceRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.owner1.email, password: SEED_CREDENTIALS.owner1.password }),
      })
    );
    aliceToken = aliceRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    const seedDocs = await db
      .select()
      .from(schema.documents)
      .where(eq(schema.documents.title, 'Meridian Logistics Q3 Financial Audit'));
    aliceDocId = seedDocs[0].id;
  });

  beforeEach(() => {
    resetIpRateLimitStoreForTests();
  });

  describe('1. Middleware Security Headers & CSRF Protection', () => {
    it('applies strict Content-Security-Policy, HSTS, frame-ancestors, and nosniff headers', () => {
      const req = new NextRequest('http://localhost:3000/api/health', {
        headers: { host: 'localhost:3000' },
      });
      const res = middleware(req);

      expect(res.headers.get('Content-Security-Policy')).toContain("frame-ancestors 'none'");
      expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
      expect(res.headers.get('X-Frame-Options')).toBe('DENY');
      expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=31536000');
      expect(res.headers.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
      expect(res.headers.get('Permissions-Policy')).toContain('camera=()');
    });

    it('rejects state-mutating requests with cookie if Origin header is missing (CSRF defense)', () => {
      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: {
          host: 'localhost:3000',
          cookie: `${SESSION_COOKIE_NAME}=${aliceToken}`,
        },
      });
      const res = middleware(req);
      expect(res.status).toBe(403);
    });

    it('rejects state-mutating requests with foreign Origin (CSRF cross-site defense)', () => {
      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: {
          host: 'localhost:3000',
          origin: 'https://evil-attacker.com',
          cookie: `${SESSION_COOKIE_NAME}=${aliceToken}`,
        },
      });
      const res = middleware(req);
      expect(res.status).toBe(403);
    });

    it('permits state-mutating requests when Origin matches Host', () => {
      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: {
          host: 'localhost:3000',
          origin: 'http://localhost:3000',
          cookie: `${SESSION_COOKIE_NAME}=${aliceToken}`,
        },
      });
      const res = middleware(req);
      expect(res.status).toBe(200); // middleware passes through
    });
  });

  describe('2. Upload Polyglot & Extension Mismatch Rejection', () => {
    it('rejects uploads with mismatched extension and magic bytes (polyglot attack)', async () => {
      // Fake PNG header in a file named .pdf
      const fakePngBuffer = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x01]);
      const formData = new FormData();
      formData.append('file', new Blob([fakePngBuffer]), 'malicious_polyglot.pdf');
      formData.append('title', 'Polyglot PDF');

      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}` },
        body: formData,
      });

      const res = await uploadHandler(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toContain('File extension mismatch');
    });

    it('rejects executable extension (.exe) uploads immediately', async () => {
      const exeBuffer = Buffer.from([0x4D, 0x5A, 0x90, 0x00]); // MZ header
      const formData = new FormData();
      formData.append('file', new Blob([exeBuffer]), 'payload.exe');
      formData.append('title', 'Payload');

      const req = new NextRequest('http://localhost:3000/api/documents', {
        method: 'POST',
        headers: { authorization: `Bearer ${aliceToken}` },
        body: formData,
      });

      const res = await uploadHandler(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toContain('strictly prohibited');
    });
  });

  describe('3. Endpoint Rate Limiting Defenses', () => {
    it('rate limits autocomplete requests when query rate threshold is exceeded', async () => {
      const makeReq = () =>
        autocompleteHandler(
          new NextRequest('http://localhost:3000/api/users/autocomplete?q=carol', {
            headers: { authorization: `Bearer ${aliceToken}` },
          })
        );

      let triggered429 = false;
      for (let i = 0; i < 35; i++) {
        const res = await makeReq();
        if (res.status === 429) {
          triggered429 = true;
          break;
        }
      }
      expect(triggered429).toBe(true);
    });

    it('requires minimum 3 characters for autocomplete to prevent user enumeration', async () => {
      const res = await autocompleteHandler(
        new NextRequest('http://localhost:3000/api/users/autocomplete?q=ca', {
          headers: { authorization: `Bearer ${aliceToken}` },
        })
      );
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error.message).toContain('at least 3 characters');
    });

    it('rate limits share requests when share threshold is exceeded', async () => {
      let triggered429 = false;
      for (let i = 0; i < 35; i++) {
        const req = new NextRequest(`http://localhost:3000/api/documents/${aliceDocId}/grants`, {
          method: 'POST',
          headers: { authorization: `Bearer ${aliceToken}`, 'content-type': 'application/json' },
          body: JSON.stringify({
            targetEmail: SEED_CREDENTIALS.viewer.email,
            permission: 'READ',
          }),
        });
        const res = await grantHandler(req, { params: { id: aliceDocId } });
        if (res.status === 429) {
          triggered429 = true;
          break;
        }
      }
      expect(triggered429).toBe(true);
    });
  });
});
