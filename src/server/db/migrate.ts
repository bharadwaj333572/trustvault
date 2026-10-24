import { rawClient } from './index';

export async function runMigrations() {
  console.log('Running TrustVault schema migrations and security triggers...');

  const migrationSql = `
    -- 1. Users Table
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'VIEWER',
      is_disabled BOOLEAN NOT NULL DEFAULT FALSE,
      failed_login_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

    -- 2. Sessions Table
    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      ip_address TEXT,
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

    -- 3. Documents Table
    CREATE TABLE IF NOT EXISTS documents (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      original_file_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      storage_key TEXT NOT NULL UNIQUE,
      sha256_checksum TEXT NOT NULL,
      category TEXT NOT NULL DEFAULT 'OTHER',
      folder_path TEXT NOT NULL DEFAULT '/',
      owner_id TEXT NOT NULL REFERENCES users(id),
      is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
      deleted_at TIMESTAMPTZ,
      current_version INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
    CREATE INDEX IF NOT EXISTS idx_documents_category ON documents(category);
    CREATE INDEX IF NOT EXISTS idx_documents_is_deleted ON documents(is_deleted);
    CREATE INDEX IF NOT EXISTS idx_documents_created_at ON documents(created_at);

    -- 4. Document Versions Table
    CREATE TABLE IF NOT EXISTS document_versions (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      version_number INTEGER NOT NULL,
      storage_key TEXT NOT NULL UNIQUE,
      original_file_name TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      sha256_checksum TEXT NOT NULL,
      created_by TEXT NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_doc_versions_doc_id ON document_versions(document_id);

    -- 5. Document Grants Table
    CREATE TABLE IF NOT EXISTS document_grants (
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      permission TEXT NOT NULL DEFAULT 'READ',
      expires_at TIMESTAMPTZ,
      granted_by TEXT NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      CONSTRAINT uq_doc_user UNIQUE (document_id, user_id)
    );

    CREATE INDEX IF NOT EXISTS idx_grants_user_id ON document_grants(user_id);
    CREATE INDEX IF NOT EXISTS idx_grants_doc_id ON document_grants(document_id);
    CREATE INDEX IF NOT EXISTS idx_grants_expires_at ON document_grants(expires_at);

    -- 6. Audit Logs Table (Tamper-evident append-only)
    CREATE TABLE IF NOT EXISTS audit_logs (
      sequence_number SERIAL PRIMARY KEY,
      id TEXT NOT NULL UNIQUE,
      prev_hash TEXT NOT NULL,
      row_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
      actor_email TEXT,
      actor_role TEXT,
      ip_address TEXT,
      user_agent TEXT,
      document_id TEXT,
      action TEXT NOT NULL,
      outcome TEXT NOT NULL,
      reason TEXT,
      details TEXT,
      request_id TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_document_id ON audit_logs(document_id);
    CREATE INDEX IF NOT EXISTS idx_audit_actor_id ON audit_logs(actor_id);
    CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit_logs(outcome);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);

    -- 7. Chain Checkpoints Table (External anchor and tail truncation detection)
    CREATE TABLE IF NOT EXISTS chain_checkpoints (
      id TEXT PRIMARY KEY,
      sequence_number INTEGER NOT NULL,
      chain_head_hash TEXT NOT NULL,
      checkpoint_type TEXT NOT NULL DEFAULT 'PERIODIC',
      hmac_signature TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_checkpoints_seq ON chain_checkpoints(sequence_number);
    CREATE INDEX IF NOT EXISTS idx_checkpoints_created ON chain_checkpoints(created_at);

    -- 8. PL/pgSQL Function and Triggers for Append-Only Enforcement
    CREATE OR REPLACE FUNCTION prevent_audit_mutation()
    RETURNS TRIGGER AS $$
    BEGIN
      RAISE EXCEPTION 'TrustVault Security Violation: The audit_logs table is append-only. UPDATE and DELETE operations are strictly prohibited.';
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS audit_log_no_update ON audit_logs;
    CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

    DROP TRIGGER IF EXISTS audit_log_no_delete ON audit_logs;
    CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
  `;

  if ('exec' in (rawClient as any)) {
    await (rawClient as any).exec(migrationSql);
  } else {
    await (rawClient as any).query(migrationSql);
  }
  console.log('✓ Database schema and security triggers applied successfully.');
}

if (require.main === module) {
  runMigrations()
    .then(() => {
      console.log('Migration complete.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('Migration failed:', err);
      process.exit(1);
    });
}
