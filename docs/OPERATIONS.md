# TrustVault — Operations & Security Administration Manual

> **Document Classification**: Confidential / Security Engineering & Operations  
> **Target Audience**: Infrastructure Administrators, Site Reliability Engineers, Security Auditors

---

## 1. Database Privilege Separation & Role Hardening

TrustVault strictly adheres to privilege separation at the database engine tier. Under no circumstances should the Next.js runtime connect to PostgreSQL as `postgres`, `rds_superuser`, or a schema owner role.

### 1.1 Three-Tier Role Model

```
┌─────────────────────────────────┐
│       trustvault_owner          │  Runs migrations, schema changes, creates tables & triggers
└────────────────┬────────────────┘
                 │ (Grants least-privilege DML)
┌────────────────▼────────────────┐
│        trustvault_app           │  Next.js runtime: SELECT/INSERT/UPDATE on data;
│                                 │  INSERT+SELECT ONLY on audit_logs (NO UPDATE, NO DELETE, NO TRIGGER)
└─────────────────────────────────┘
┌─────────────────────────────────┐
│      trustvault_auditor         │  Read-only analytical role: SELECT on audit_logs & checkpoints only
└─────────────────────────────────┘
```

### 1.2 PostgreSQL Provisioning Script

Execute the following SQL commands as cluster superuser during initial provisioning:

```sql
-- 1. Create Migration Owner Role
CREATE ROLE trustvault_owner WITH LOGIN PASSWORD 'strong_owner_password';
GRANT ALL PRIVILEGES ON DATABASE trustvault TO trustvault_owner;

-- 2. Create Application Runtime Role (Least Privilege)
CREATE ROLE trustvault_app WITH LOGIN PASSWORD 'strong_app_password';
GRANT CONNECT ON DATABASE trustvault TO trustvault_app;

-- Connect to target database
\c trustvault

-- Ensure schema belongs to owner
ALTER SCHEMA public OWNER TO trustvault_owner;

-- Grant standard DML to app role on operational tables
GRANT SELECT, INSERT, UPDATE, DELETE ON users, sessions, documents, document_versions, document_grants TO trustvault_app;

-- STRICT AUDIT LOG RESTRICTION:
-- Runtime app role is granted INSERT and SELECT only on audit_logs and chain_checkpoints
GRANT SELECT, INSERT ON audit_logs, chain_checkpoints TO trustvault_app;

-- REVOKE ALL MUTATION PRIVILEGES from app role:
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs, chain_checkpoints FROM trustvault_app;
REVOKE TRIGGER ON audit_logs FROM trustvault_app;

-- 3. Create External Read-Only Auditor Role
CREATE ROLE trustvault_auditor WITH LOGIN PASSWORD 'auditor_password';
GRANT CONNECT ON DATABASE trustvault TO trustvault_auditor;
GRANT SELECT ON audit_logs, chain_checkpoints TO trustvault_auditor;
```

---

## 2. Superuser Tampering & External Anchoring

### 2.1 The Inherent Superuser Threat
In any relational database system (PostgreSQL, MySQL, Oracle), a principal authenticated as database superuser (`postgres`, `root`) has raw block-level authority and can bypass database triggers:

```sql
-- What a compromised DB superuser can execute:
ALTER TABLE audit_logs DISABLE TRIGGER ALL;
UPDATE audit_logs SET outcome = 'ALLOWED' WHERE document_id = 'target-id';
ALTER TABLE audit_logs ENABLE TRIGGER ALL;
```

Database triggers protect the audit trail against malicious application code, SQL injections, and compromised application database roles (`trustvault_app`). **Triggers alone cannot stop an infrastructure-level cloud superuser.**

### 2.2 How the External Anchor Catches Superuser Tampering
To defeat superuser tampering and tail truncation, TrustVault implements **cryptographic external anchoring**:

1. **HMAC Signature with Isolated Secret**: Checkpoints in `chain_checkpoints` are signed using HMAC-SHA256 with `AUDIT_HMAC_SECRET`. This secret is maintained outside database access (e.g., AWS Secrets Manager or KMS) and is never accessible to the database superuser.
2. **Periodic & On-Demand Checkpoints**: Checkpoints record the exact `sequence_number`, `row_hash`, and HMAC signature at regular intervals (every 10 events) and upon admin audit verification.
3. **External Archival (WORM)**: Administrators export checkpoints via `GET /api/admin/audit/checkpoint/export` and push them to external Write-Once-Read-Many (WORM) storage (AWS S3 Glacier Object Lock or GCS Bucket Lock).
4. **Tamper & Truncation Detection**:
   - If a superuser modifies an intermediate row, the SHA-256 chain breaks at that sequence number.
   - If a superuser drops the latest $k$ rows to hide recent exfiltration, `verifyChain()` compares the live table head against the latest verified checkpoint and reports:
     `TRUNCATED: expected sequence #n, found live head #m`.

---

## 3. Cryptographic Chain Verification

### 3.1 On-Demand Verification
Administrators can verify the entire cryptographic audit chain at any time through the Admin Dashboard or via HTTP API:

```bash
curl -X GET "https://vault.example.com/api/admin/audit/verify" \
  -H "Authorization: Bearer <ADMIN_SESSION_TOKEN>"
```

#### Response Structure:
```json
{
  "valid": true,
  "badge": "CHAIN VERIFIED",
  "verifiedBlocks": 248,
  "latestSequence": 248,
  "chainHead": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "verifiedAt": "2026-10-25T12:00:00.000Z"
}
```

### 3.2 Automated Chain Audit Script
Run the automated verification script from cron or CI/CD pipelines:

```bash
npm run audit:verify
```

Exit code `0` indicates an unbroken, non-truncated chain. Exit code `1` triggers immediate security alerts.

---

## 4. Disaster Recovery & Backups

### 4.1 Database Snapshot Backup
Perform logical database backups using `pg_dump`:

```bash
pg_dump -U trustvault_owner -h localhost -d trustvault \
  --format=custom \
  --file=/backups/trustvault_$(date +%Y%m%d_%H%M%S).dump
```

### 4.2 Storage Volume Synchronization
The private storage root (`STORAGE_DIR`, default `./storage`) holds encrypted file payloads indexed by opaque random UUIDs. Synchronize the storage directory alongside database snapshots:

```bash
aws s3 sync /data/trustvault/storage s3://trustvault-backups-immutable/storage/ \
  --sse aws:kms \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "2036-01-01T00:00:00Z"
```

---

## 5. Key & Secret Rotation Playbooks

### 5.1 Rotating Session Secret (`SESSION_SECRET`)
1. Generate high-entropy 256-bit random key:
   ```bash
   openssl rand -hex 32
   ```
2. Update `SESSION_SECRET` in environment or secret manager.
3. Restart Next.js processes. Because sessions are database-backed and tokens are SHA-256 hashed on insert, rotating the cookie encryption secret invalidates unauthenticated forge attempts without forcibly dropping existing DB sessions.

### 5.2 Rotating Audit HMAC Secret (`AUDIT_HMAC_SECRET`)
1. Generate new HMAC key:
   ```bash
   openssl rand -hex 32
   ```
2. Export the final checkpoint under the outgoing secret:
   ```bash
   curl -X GET "https://vault.example.com/api/admin/audit/checkpoint/export" \
     -H "Authorization: Bearer <ADMIN_SESSION_TOKEN>" > checkpoint_anchor_v1.json
   ```
3. Update `AUDIT_HMAC_SECRET` in application environment and deploy.
4. Issue immediate verify call (`GET /api/admin/audit/verify`) to initialize the first checkpoint under the new key.

---

## 6. Incident Response Playbooks

### 6.1 Emergency Account Lockdown & Instant Session Invalidation
When an employee leaves the company or a user account is compromised:

1. Navigate to **Admin Console -> Users Directory**.
2. Click **Disable Account** on the target user.
3. **Automated Enforcement**:
   - The user record is set to `is_disabled = true`.
   - All active database sessions for that user across all devices/browsers are deleted immediately (`revokeAllUserSessions()`).
   - Any in-flight file downloads are terminated at the next 64 KB chunk boundary.
   - Future requests return `401 Unauthorized` / `403 Forbidden`.

### 6.2 Forensic Audit: "Who Opened Document X and When?"
If sensitive intellectual property or financial records are suspected of being leaked:

1. Open **Admin Console -> Global Audit Explorer**.
2. Paste the target `Document ID` into the **Document ID Filter**.
3. Select Action **DOWNLOADS ONLY** or **ALL ACTIONS**.
4. The system executes a single indexed SQL query against `audit_logs` filtering strictly on `document_id`.
5. Review the chronological access list:
   - Sequence number in immutable hash chain
   - Timestamp (UTC)
   - Actor email and authenticated role
   - Client IP address and User Agent
   - Byte range accessed (`bytes=0-1048576` or `FULL_PAYLOAD`)
   - Outcome (`ALLOWED` or `DENIED` with reason)
6. Export the forensic report to CSV:
   ```bash
   curl -X GET "https://vault.example.com/api/admin/audit?documentId=<DOC_ID>&format=csv" \
     -H "Authorization: Bearer <ADMIN_TOKEN>" > forensic_report_<DOC_ID>.csv
   ```
