import { describe, it, expect, beforeAll } from 'vitest';
import { NextRequest } from 'next/server';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase } from '../../scripts/seed';
import { db, schema } from '@/server/db';
import { eq } from 'drizzle-orm';
import { POST as registerHandler } from '@/app/api/auth/register/route';
import { verifyPassword } from '@/server/auth/password';
import { SESSION_COOKIE_NAME } from '@/server/auth/session';

describe('Public Self-Registration (Gmail & Corporate Accounts)', () => {
  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();
  });

  it('successfully registers a new Gmail user with OWNER role, Argon2id hash, and active session', async () => {
    const testEmail = `newuser.${Date.now()}@gmail.com`;
    const testName = 'Chintu Patil';
    const testPassword = 'StrongPassword123!';

    const req = new NextRequest('http://localhost:3000/api/auth/register', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-forwarded-for': '192.168.1.100',
        'user-agent': 'Vitest-Test-Browser',
      },
      body: JSON.stringify({
        fullName: testName,
        email: testEmail,
        password: testPassword,
      }),
    });

    const res = await registerHandler(req);
    expect(res.status).toBe(201);

    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.user).toBeDefined();
    expect(data.user.email).toBe(testEmail.toLowerCase());
    expect(data.user.fullName).toBe(testName);
    expect(data.user.role).toBe('OWNER');

    // Verify session cookie was set
    const setCookie = res.headers.get('set-cookie');
    expect(setCookie).toBeTruthy();
    expect(setCookie).toContain(SESSION_COOKIE_NAME);

    // Verify user in database
    const [dbUser] = await db
      .select()
      .from(schema.users)
      .where(eq(schema.users.email, testEmail.toLowerCase()));

    expect(dbUser).toBeDefined();
    expect(dbUser.fullName).toBe(testName);
    expect(dbUser.role).toBe('OWNER');
    expect(dbUser.isDisabled).toBe(false);

    // Verify password was securely hashed with Argon2id
    const passwordValid = await verifyPassword(dbUser.passwordHash, testPassword);
    expect(passwordValid).toBe(true);
  });

  it('rejects registration if the email is already in use', async () => {
    const existingEmail = 'alice.owner@meridian.test';

    const req = new NextRequest('http://localhost:3000/api/auth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Alice Duplicate',
        email: existingEmail,
        password: 'Password999!',
      }),
    });

    const res = await registerHandler(req);
    expect(res.status).toBe(409);

    const data = await res.json();
    expect(data.error?.code).toBe('USER_EXISTS');
  });

  it('rejects passwords shorter than 8 characters', async () => {
    const req = new NextRequest('http://localhost:3000/api/auth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        fullName: 'Short Pass User',
        email: 'shortpass@example.com',
        password: 'short',
      }),
    });

    const res = await registerHandler(req);
    expect(res.status).toBe(400);

    const data = await res.json();
    expect(data.error?.code).toBe('VALIDATION_ERROR');
  });
});
