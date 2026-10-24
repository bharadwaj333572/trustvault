import { drizzle as drizzlePg } from 'drizzle-orm/node-postgres';
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite';
import { PGlite } from '@electric-sql/pglite';
import { Pool } from 'pg';
import * as schema from './schema';
import path from 'path';
import fs from 'fs';

// Global singleton to avoid multi-instance issues in Next.js hot-reloading
const globalForDb = globalThis as unknown as {
  dbInstance?: ReturnType<typeof drizzlePg<typeof schema>> | ReturnType<typeof drizzlePglite<typeof schema>>;
  rawClient?: Pool | PGlite;
};

export function getDatabase() {
  if (globalForDb.dbInstance && globalForDb.rawClient) {
    return { db: globalForDb.dbInstance, rawClient: globalForDb.rawClient };
  }

  const databaseUrl = process.env.DATABASE_URL;

  if (databaseUrl && (databaseUrl.startsWith('postgres://') || databaseUrl.startsWith('postgresql://'))) {
    const pool = new Pool({
      connectionString: databaseUrl,
      max: 10,
      idleTimeoutMillis: 30000,
    });
    const db = drizzlePg(pool, { schema });
    globalForDb.dbInstance = db;
    globalForDb.rawClient = pool;
    return { db, rawClient: pool };
  } else {
    // Local / test fallback using PGlite
    const dataDir = process.env.NODE_ENV === 'test' 
      ? undefined 
      : path.resolve(process.cwd(), '.pgdata');

    if (dataDir && !fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const pglite = dataDir ? new PGlite(dataDir) : new PGlite();
    const db = drizzlePglite(pglite, { schema });
    globalForDb.dbInstance = db;
    globalForDb.rawClient = pglite;
    return { db, rawClient: pglite };
  }
}

export const { db, rawClient } = getDatabase();
export { schema };
