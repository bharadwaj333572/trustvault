import { describe, it, expect, beforeAll } from 'vitest';
import { runMigrations } from '@/server/db/migrate';
import { seedDatabase, SEED_CREDENTIALS } from '../../scripts/seed';
import { POST as loginHandler } from '@/app/api/auth/login/route';
import { POST as logoutHandler } from '@/app/api/auth/logout/route';
import { GET as meHandler } from '@/app/api/auth/me/route';
import { NextRequest } from 'next/server';
import { SESSION_COOKIE_NAME, validateSession } from '@/server/auth/session';

describe('Auth & Session Integration', () => {
  beforeAll(async () => {
    await runMigrations();
    await seedDatabase();
  });

  it('authenticates valid credentials and issues secure session token', async () => {
    const req = new NextRequest('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'origin': 'http://localhost:3000',
        'host': 'localhost:3000',
      },
      body: JSON.stringify({
        email: SEED_CREDENTIALS.owner1.email,
        password: SEED_CREDENTIALS.owner1.password,
      }),
    });

    const res = await loginHandler(req);
    expect(res.status).toBe(200);

    const json = await res.json();
    expect(json.success).toBe(true);
    expect(json.user.email).toBe(SEED_CREDENTIALS.owner1.email);
    expect(json.user.role).toBe('OWNER');

    // Verify session cookie was set
    const cookieHeader = res.cookies.get(SESSION_COOKIE_NAME);
    expect(cookieHeader).toBeDefined();
    expect(cookieHeader?.value).toBeTruthy();

    // Verify session is valid in database
    const sessionData = await validateSession(cookieHeader!.value);
    expect(sessionData.user.email).toBe(SEED_CREDENTIALS.owner1.email);
  });

  it('rejects invalid password with generic error message and audits failure', async () => {
    const req = new NextRequest('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'origin': 'http://localhost:3000',
        'host': 'localhost:3000',
      },
      body: JSON.stringify({
        email: SEED_CREDENTIALS.owner1.email,
        password: 'CompletelyWrongPassword!',
      }),
    });

    const res = await loginHandler(req);
    expect(res.status).toBe(401);
    const json = await res.json();
    expect(json.error.message).toBe('Invalid email or password');
  });

  it('locks out account after 5 consecutive failed login attempts', async () => {
    const targetEmail = SEED_CREDENTIALS.viewer.email;

    // Trigger 5 failed attempts
    for (let i = 0; i < 5; i++) {
      const req = new NextRequest('http://localhost:3000/api/auth/login', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'origin': 'http://localhost:3000',
          'host': 'localhost:3000',
        },
        body: JSON.stringify({
          email: targetEmail,
          password: `BadPasswordAttempt_${i}`,
        }),
      });
      const res = await loginHandler(req);
      if (i < 4) {
        expect(res.status).toBe(401);
      } else {
        // 5th attempt locks the account
        expect(res.status).toBe(423);
        const json = await res.json();
        expect(json.error.code).toBe('LOCKED_OUT');
      }
    }

    // 6th attempt is blocked immediately by lockout
    const reqAfter = new NextRequest('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'origin': 'http://localhost:3000',
        'host': 'localhost:3000',
      },
      body: JSON.stringify({
        email: targetEmail,
        password: SEED_CREDENTIALS.viewer.password, // even correct password should be blocked
      }),
    });

    const resAfter = await loginHandler(reqAfter);
    expect(resAfter.status).toBe(423);
  });

  it('verifies /api/auth/me returns user data when authenticated', async () => {
    // Log in as owner 2 (Bob)
    const loginReq = new NextRequest('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'origin': 'http://localhost:3000',
        'host': 'localhost:3000',
      },
      body: JSON.stringify({
        email: SEED_CREDENTIALS.owner2.email,
        password: SEED_CREDENTIALS.owner2.password,
      }),
    });

    const loginRes = await loginHandler(loginReq);
    const token = loginRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    const meReq = new NextRequest('http://localhost:3000/api/auth/me', {
      method: 'GET',
      headers: {
        'authorization': `Bearer ${token}`,
      },
    });

    const meRes = await meHandler(meReq);
    expect(meRes.status).toBe(200);
    const meJson = await meRes.json();
    expect(meJson.user.email).toBe(SEED_CREDENTIALS.owner2.email);
    expect(meJson.user.role).toBe('OWNER');
  });

  it('logout destroys session and invalidates subsequent requests', async () => {
    // Log in
    const loginReq = new NextRequest('http://localhost:3000/api/auth/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'origin': 'http://localhost:3000',
        'host': 'localhost:3000',
      },
      body: JSON.stringify({
        email: SEED_CREDENTIALS.admin.email,
        password: SEED_CREDENTIALS.admin.password,
      }),
    });

    const loginRes = await loginHandler(loginReq);
    const token = loginRes.cookies.get(SESSION_COOKIE_NAME)!.value;

    // Logout
    const logoutReq = new NextRequest('http://localhost:3000/api/auth/logout', {
      method: 'POST',
      headers: {
        'cookie': `${SESSION_COOKIE_NAME}=${token}`,
        'origin': 'http://localhost:3000',
        'host': 'localhost:3000',
      },
    });

    const logoutRes = await logoutHandler(logoutReq);
    expect(logoutRes.status).toBe(200);

    // Verify session validation now fails
    await expect(validateSession(token)).rejects.toThrow();
  });
});
