import { NextResponse } from 'next/server';
import fs from 'fs';
import path from 'path';
import { rawClient } from '@/server/db';

function readAppVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.resolve(process.cwd(), 'package.json'), 'utf8'));
    return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * Public health endpoint. Must never reveal document titles, counts, owners, or existence.
 * Returns application version and whether core schema objects are present.
 */
export async function GET() {
  let migrationStatus: 'ok' | 'degraded' = 'ok';
  let schemaReady = false;

  try {
    if ('query' in (rawClient as any)) {
      const result = await (rawClient as any).query(
        `SELECT to_regclass('public.users') IS NOT NULL AS users_ok,
                to_regclass('public.audit_logs') IS NOT NULL AS audit_ok`
      );
      const row = result.rows?.[0] || result?.[0];
      schemaReady = Boolean(row?.users_ok && row?.audit_ok);
    } else if ('exec' in (rawClient as any)) {
      await (rawClient as any).exec('SELECT 1 FROM users LIMIT 1');
      await (rawClient as any).exec('SELECT 1 FROM audit_logs LIMIT 1');
      schemaReady = true;
    }
  } catch {
    migrationStatus = 'degraded';
    schemaReady = false;
  }

  if (!schemaReady) {
    migrationStatus = 'degraded';
  }

  return NextResponse.json({
    status: migrationStatus === 'ok' ? 'healthy' : 'degraded',
    version: readAppVersion(),
    migrationStatus,
    schemaReady,
    timestamp: new Date().toISOString(),
  });
}
