import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { GET as getDocumentHandler } from '@/app/api/documents/[id]/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import crypto from 'crypto';

describe('Existence Leak by Timing Side-Channel Defense', () => {
  let viewerToken: string;
  let forbiddenDocId: string;
  const missingDocId = crypto.randomUUID();

  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();

    // Authenticate Viewer (Carol)
    const carolRes = await loginHandler(
      new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'http://localhost:3000', host: 'localhost:3000' },
        body: JSON.stringify({ email: SEED_CREDENTIALS.viewer.email, password: SEED_CREDENTIALS.viewer.password }),
      })
    );
    viewerToken = carolRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Locate Bob's document (forbidden to Carol)
    const seedDocs = await db
      .select()
      .from(schema.documents)
      .where(eq(schema.documents.title, 'Project Zephyr Hardware Schematics'));
    forbiddenDocId = seedDocs[0].id;
  });

  it('ensures both missing and forbidden documents return uniform 404 responses', async () => {
    // Missing document request
    const missingReq = new NextRequest(`http://localhost:3000/api/documents/${missingDocId}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${viewerToken}` },
    });
    const missingRes = await getDocumentHandler(missingReq, { params: { id: missingDocId } });
    expect(missingRes.status).toBe(404);
    const missingJson = await missingRes.json();
    expect(missingJson.error.code).toBe('NOT_FOUND');

    // Forbidden document request
    const forbiddenReq = new NextRequest(`http://localhost:3000/api/documents/${forbiddenDocId}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${viewerToken}` },
    });
    const forbiddenRes = await getDocumentHandler(forbiddenReq, { params: { id: forbiddenDocId } });
    expect(forbiddenRes.status).toBe(404);
    const forbiddenJson = await forbiddenRes.json();
    expect(forbiddenJson.error.code).toBe('NOT_FOUND');

    // Ensure error responses are byte-identical in structure
    expect(Object.keys(missingJson.error).sort()).toEqual(Object.keys(forbiddenJson.error).sort());
  });

  it('measures response times for missing vs forbidden and confirms they are within tolerance', async () => {
    // Warmup JIT / DB cache
    for (let i = 0; i < 3; i++) {
      const warmupReq1 = new NextRequest(`http://localhost:3000/api/documents/${missingDocId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${viewerToken}` },
      });
      await getDocumentHandler(warmupReq1, { params: { id: missingDocId } });

      const warmupReq2 = new NextRequest(`http://localhost:3000/api/documents/${forbiddenDocId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${viewerToken}` },
      });
      await getDocumentHandler(warmupReq2, { params: { id: forbiddenDocId } });
    }

    const missingTimes: number[] = [];
    const forbiddenTimes: number[] = [];
    const SAMPLES = 10;

    for (let i = 0; i < SAMPLES; i++) {
      // Benchmark missing
      const t0 = performance.now();
      const mReq = new NextRequest(`http://localhost:3000/api/documents/${missingDocId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${viewerToken}` },
      });
      await getDocumentHandler(mReq, { params: { id: missingDocId } });
      missingTimes.push(performance.now() - t0);

      // Benchmark forbidden
      const t1 = performance.now();
      const fReq = new NextRequest(`http://localhost:3000/api/documents/${forbiddenDocId}`, {
        method: 'GET',
        headers: { authorization: `Bearer ${viewerToken}` },
      });
      await getDocumentHandler(fReq, { params: { id: forbiddenDocId } });
      forbiddenTimes.push(performance.now() - t1);
    }

    const mean = (arr: number[]) => arr.reduce((a, b) => a + b, 0) / arr.length;
    const meanMissing = mean(missingTimes);
    const meanForbidden = mean(forbiddenTimes);
    const diffMs = Math.abs(meanMissing - meanForbidden);

    console.log(`[Timing Benchmark] Missing: ${meanMissing.toFixed(2)}ms | Forbidden: ${meanForbidden.toFixed(2)}ms | Delta: ${diffMs.toFixed(2)}ms`);

    // Stated tolerance: timing difference must be under 35ms in local execution
    expect(diffMs).toBeLessThan(35);
  });
});
