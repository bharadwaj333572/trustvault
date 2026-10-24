# TrustVault Technical Architecture Specification

> **System Promise**: "The wrong person can never read a file, and we can prove who read it."

TrustVault is an enterprise document security system built from first principles around adversarial authorization and tamper-evident auditing. This document details the architectural decisions, security boundaries, and data flows governing the entire system.

---

## 1. System Overview & Architectural Diagram

```
+-----------------------------------------------------------------------------------+
|                                CLIENT BROWSER                                     |
|    - Industrial UI (Dark/Light Tokens, JetBrains Mono, Inter, Archivo)            |
|    - HttpOnly, SameSite=Lax, Secure Session Cookie (Random 128-bit Opaque Token)   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v  HTTPS / TLS 1.3
+-----------------------------------------------------------------------------------+
|                        EDGE & MIDDLEWARE SECURITY LAYER                           |
|    - Security Headers: CSP, HSTS, X-Content-Type-Options: nosniff, Frame-Ancestors|
|    - CSRF Protection: Strict Origin & Host header validation                      |
|    - Rate Limiting & Progressive Lockout: 5 failed attempts -> 15 min lock       |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                         CENTRAL POLICY ENGINE (can())                             |
|    - Sole authorization chokepoint across all routes and services                 |
|    - Pure function: can(user, action, document, grants, currentTime)              |
|    - Default DENY architecture; Admin isolated from document contents             |
|    - Uniform 404 response shape: zero existence leakage                          |
+-------------------+---------------------+--------------------+--------------------+
                    |                     |                    |
                    v                     v                    v
+-----------------------+ +-------------------------+ +-----------------------------+
|    STORAGE ADAPTER    | |     SESSION MANAGER     | |   TAMPER-EVIDENT AUDIT      |
| - Stream through API  | | - DB-backed sessions    | | - Cryptographic Hash Chain  |
| - Magic byte sniffing | | - Immediate revocation  | | - SHA-256(prev_hash + JSON) |
| - UUID storage keys   | | - User disable purges   | | - BEFORE UPDATE/DELETE      |
| - No direct S3 URLs   | |   all active sessions   | |   Triggers (IMMUTABLE)      |
+-----------------------+ +-------------------------+ +-----------------------------+
                    |                     |                    |
                    +---------------------+--------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                     POSTGRESQL / PGLITE PERSISTENCE LAYER                         |
|    - Parameterized SQL (Drizzle ORM)                                              |
|    - Tables: users, sessions, documents, document_versions,                       |
|              document_grants, audit_logs                                          |
+-----------------------------------------------------------------------------------+
```

---

## 2. Database Schema & Data Models

The persistence layer uses PostgreSQL (with embedded PGlite for self-contained, zero-configuration local runs and automated CI testing).

### 2.1 Schema Tables

1. **`users`**
   - `id` (UUID PK): Unique user identifier.
   - `email` (TEXT UNIQUE): User email address.
   - `password_hash` (TEXT): Argon2id password hash (19 MiB memory cost, 2 iterations, 1 parallelism).
   - `full_name` (TEXT): Human display name.
   - `role` (TEXT): Enum `'ADMIN' | 'OWNER' | 'VIEWER'`.
   - `is_disabled` (BOOLEAN): Immediate account suspension flag.
   - `failed_login_attempts` (INT): Counter for lockout enforcement.
   - `locked_until` (TIMESTAMPTZ): Lockout expiration timestamp.

2. **`sessions`**
   - `id` (UUID PK): Unique session record id.
   - `user_id` (UUID FK -> users.id): Owning user.
   - `token_hash` (TEXT UNIQUE): SHA-256 hash of the opaque cookie token.
   - `ip_address`, `user_agent` (TEXT): Security metadata.
   - `expires_at` (TIMESTAMPTZ): Absolute expiration time (7 days maximum lifetime).

3. **`documents`**
   - `id` (UUID PK): Document identifier.
   - `title` (TEXT): Sanitized display title.
   - `original_file_name` (TEXT): Sanitized filename (stripped of paths and control characters).
   - `mime_type` (TEXT): Sniffed magic byte MIME type (`application/pdf`, etc.).
   - `file_size` (BIGINT): File byte length.
   - `storage_key` (TEXT UNIQUE): Opaque UUID path on the private volume.
   - `sha256_checksum` (TEXT): Cryptographic digest of file payload for integrity verification.
   - `category` (TEXT): Business category (`FINANCIAL`, `LEGAL`, `HR`, `ENGINEERING`, `OPERATIONS`, `OTHER`).
   - `folder_path` (TEXT): Virtual organization folder.
   - `owner_id` (UUID FK -> users.id): Document owner.
   - `is_deleted` (BOOLEAN): Soft-deletion flag.
   - `deleted_at` (TIMESTAMPTZ): Soft-deletion timestamp.
   - `current_version` (INT): Current version integer.

4. **`document_versions`**
   - `id` (UUID PK): Version record id.
   - `document_id` (UUID FK -> documents.id): Parent document.
   - `version_number` (INT): Incremental version index.
   - `storage_key` (TEXT): Storage key for this version's payload.
   - `original_file_name`, `file_size`, `sha256_checksum`: Version payload metadata.
   - `created_by` (UUID FK -> users.id): Version author.

5. **`document_grants`**
   - `id` (UUID PK): Grant identifier.
   - `document_id` (UUID FK -> documents.id): Target document.
   - `user_id` (UUID FK -> users.id): Recipient user.
   - `permission` (TEXT): Permission level `'READ' | 'EDIT'`.
   - `granted_by` (UUID FK -> users.id): Granter user.
   - `expires_at` (TIMESTAMPTZ): Optional expiry timestamp.

6. **`audit_logs` (Append-Only)**
   - `id` (UUID PK): Audit log id.
   - `sequence_number` (BIGSERIAL UNIQUE): Monotonically increasing sequence number.
   - `timestamp` (TIMESTAMPTZ): Exact UTC timestamp.
   - `actor_id` (UUID NULLABLE): User ID (or null for unauthenticated events).
   - `actor_email` (TEXT NULLABLE): Actor email address.
   - `actor_role` (TEXT NULLABLE): Actor role at event time.
   - `ip_address`, `user_agent`, `request_id` (TEXT): Tracing metadata.
   - `document_id` (UUID NULLABLE): Target document id.
   - `action` (TEXT): Canonical event name.
   - `outcome` (TEXT): `'ALLOWED' | 'DENIED'`.
   - `reason` (TEXT NULLABLE): True reason for policy decision or denial.
   - `prev_hash` (TEXT): Cryptographic hash of the preceding block.
   - `hash` (TEXT UNIQUE): SHA-256 digest of block contents.
   - `metadata` (JSONB NULLABLE): Event-specific structured context.

---

## 3. Central Policy Engine (`can()`)

All authorization decisions in TrustVault flow through a single pure policy function located in `src/server/policy/index.ts`:

```typescript
can(
  user: AuthenticatedUser,
  action: PolicyAction,
  document: PolicyDocument,
  grants: PolicyGrant[] = [],
  currentTime: Date = new Date()
): PolicyDecision
```

### 3.1 Authorization Matrix

| Actor / Context | `view` (Metadata) | `download` (File Content) | `edit` (Title/Metadata) | `delete` (Soft Delete) | `share` (Grant/Revoke) | `viewActivity` (Audit Log) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Disabled User** | DENIED | DENIED | DENIED | DENIED | DENIED | DENIED |
| **Document Owner** | ALLOWED | ALLOWED | ALLOWED | ALLOWED | ALLOWED | ALLOWED |
| **Granted EDIT** | ALLOWED | ALLOWED | ALLOWED | DENIED | DENIED | DENIED |
| **Granted READ** | ALLOWED | ALLOWED | DENIED | DENIED | DENIED | DENIED |
| **Admin (No Grant)** | DENIED* | DENIED | DENIED | DENIED | DENIED | ALLOWED (System Log) |
| **Ungranted User** | DENIED | DENIED | DENIED | DENIED | DENIED | DENIED |
| **Expired Grant** | DENIED | DENIED | DENIED | DENIED | DENIED | DENIED |

*\*Admin can view global system audit metadata in the Admin panel, but cannot view individual document detail views or download document contents unless explicitly granted like any other user.*

### 3.2 Uniform 404 Response & Anti-Timing

When a user requests a document they are not authorized to view, or a document that has been soft-deleted, the policy engine raises a `UniformNotFoundOrForbiddenError`. The API returns:
```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Document not found or access denied"
  }
}
```
HTTP status code is consistently `404 Not Found`. This prevents adversaries from port-scanning or enumerating document UUIDs.

---

## 4. Immediate Revocation Engine

TrustVault guarantees that **revoking a grant, disabling a user, or changing a role takes effect on the very next request**.

### 4.1 Rejection of Pre-Signed URLs
Many document systems generate pre-signed S3 URLs with expiration windows (e.g., 15 minutes to 24 hours). If access is revoked 10 seconds later, the attacker can still download the file using the valid signed URL.

TrustVault explicitly eliminates pre-signed URLs. Files are stored on a private, non-public disk/bucket. File downloads are streamed directly through `/api/documents/[id]/download`, where a real-time policy evaluation executes immediately before the first byte is streamed.

### 4.2 Instant Session Purge on Disable
When an Administrator disables an account (`PATCH /api/admin/users/[id]` with `{ isDisabled: true }`), TrustVault executes:
```typescript
await db.delete(schema.sessions).where(eq(schema.sessions.userId, targetUserId));
```
All existing active sessions for that user are immediately eradicated from the database. The disabled user's very next HTTP request fails with `401 Unauthenticated`.

---

## 5. Tamper-Evident Cryptographic Hash Chain

TrustVault maintains an append-only, tamper-evident audit log structured identically to a cryptographic blockchain.

### 5.1 Block Hash Construction
Each audit row computes its hash as:
$$\text{hash}_n = \text{SHA-256}(\text{prev\_hash}_{n-1} + \text{canonical\_json}(\text{row}_n))$$

The canonical JSON serialization strictly sorts keys and normalizes ISO 8601 timestamps to guarantee deterministic hash reproduction across any platform or runtime.

### 5.2 Genesis Block
The genesis block ($n=1$) uses the initial seed anchor:
$$\text{prev\_hash}_1 = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$$

### 5.3 PostgreSQL Database Triggers
To prevent any modification or deletion of existing audit records (even by application database connections or compromised SQL credentials), PostgreSQL triggers are applied during migration:

```sql
CREATE OR REPLACE FUNCTION prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Audit trail entries are immutable. UPDATE and DELETE operations are forbidden.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_no_update_audit_logs
BEFORE UPDATE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();

CREATE TRIGGER trg_no_delete_audit_logs
BEFORE DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_modification();
```

### 5.4 Verification Algorithm
The `verifyChain()` function in `src/server/services/audit.ts` executes a full serial recomputation of every hash from block 1 to the tip. If an attacker modifies even a single character in an audit record (e.g. changing an IP address or outcome from `DENIED` to `ALLOWED`), `verifyChain()` reports:
```json
{
  "valid": false,
  "brokenAtSequence": 4,
  "expectedHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "actualHash": "1a2b3c4d..."
}
```

---

## 6. Upload Validation & Storage Architecture

### 6.1 Magic Byte Binary Sniffing
File validation never trusts client-supplied MIME types or file extensions. The first 512 bytes are inspected for unambiguous binary magic signatures:
- **PDF**: `%PDF-` (`0x25 0x50 0x44 0x46`)
- **PNG**: `\x89PNG\r\n\x1a\n`
- **JPEG**: `\xFF\xD8\xFF`
- **Office OpenXML (DOCX, XLSX, PPTX)**: PKZIP signature `\x50\x4B\x03\x04` followed by standard Office MIME detection
- **Executables Rejected**: PE (`MZ` / `0x4D 0x5A`) and ELF (`\x7F\x45\x4C\x46`) binaries are strictly rejected
- **Active Content Rejected**: HTML (`<!DOCTYPE`, `<html`, `<script`) and SVG files are rejected to neutralize stored XSS attacks

### 6.2 Opaque Storage Keys & Path Traversal Elimination
All uploaded files are assigned a cryptographically random UUID storage key:
$$\text{storageKey} = \text{UUIDv4()}$$
The original filename is sanitized using `sanitizeFileName()` (stripping directory traversal sequences such as `../`, `..\`, null bytes, and control characters) and stored purely as display metadata in the database.

Downloads are served with defensive response headers:
```http
Content-Disposition: attachment; filename="sanitized_name.pdf"
X-Content-Type-Options: nosniff
Cache-Control: private, no-store, max-age=0
```

---

## 7. Security Alert Engine

The administrative alert engine in `src/server/services/alerts.ts` continuously analyzes the immutable audit stream to identify anomalous behavioral patterns.

| Alert Identifier | Severity | Trigger Criteria | Significance |
|:---|:---:|:---|:---|
| `DENIED_SPIKE` | **HIGH** | $\ge 5$ authorization denials for a single user within 15 minutes. | Indicates active privilege escalation attempts or systematic IDOR enumeration. |
| `ODD_HOURS_ACCESS` | **MEDIUM** | Document access between 00:00 and 05:00 local time. | Detects after-hours exfiltration attempts or anomalous session activity. |
| `BULK_DOWNLOAD` | **HIGH** | $> 10$ document downloads by a single user within 10 minutes. | Identifies automated bulk exfiltration scripts. |
| `ACCOUNT_LOCKOUT` | **MEDIUM** | 5 consecutive failed login attempts leading to account lock. | Highlights credential stuffing or password spray attacks. |
| `REVOKED_USER_PROBE` | **CRITICAL** | User whose grant was revoked attempts to re-access the document within 24 hours. | Identifies insider threats testing revoked access boundaries. |

---

## 8. AI Sharing Suggestions (Safety Boundary)

TrustVault provides an optional "Sharing Suggestions" capability to simplify access management for owners while strictly adhering to safety rules:

1. **Deterministic Collaborative Filtering**: Suggestions are computed based on historical sharing co-occurrence and document category relationships (e.g., users who share financial docs frequently collaborate with auditing personnel).
2. **Zero Content Exposure**: Document content, text, and binary bytes are never transmitted to any language model or external service.
3. **No Autonomous Access Widening**: The suggestion engine cannot create grants. Suggestions are rendered purely as UI chips in the Share dialog. An authenticated human owner must explicitly click to confirm every grant.
4. **Comprehensive Auditing**: Every rendered suggestion and every user acceptance or dismissal generates a dedicated tamper-evident audit record (`ai.suggestion_shown`, `ai.suggestion_accepted`, `ai.suggestion_dismissed`).
