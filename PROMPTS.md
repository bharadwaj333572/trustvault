# TrustVault — Prompts & Human Review Log

This document records prompts, unexpected model outputs, discrepancies, and areas of uncertainty regarding authorization and audit trail integrity. Entries are logged strictly during development when real events occur.

---

## Log Template Format

```markdown
### [YYYY-MM-DD HH:MM] - Phase <Phase Number>: <Phase Name>
- **Query / Task**: What was asked or instructed.
- **Result / Model Output**: What was generated or proposed.
- **Discrepancy / Weakness**: What was incorrect, insecure, or ambiguous.
- **Resolution**: What was implemented instead and why.
- **Commit Reference**: `<commit hash>`
```

---

## Real Events & Engineering Post-Mortem Log

### [2026-10-24 18:20] - Phase 1: Bulk Migration Engine Execution
- **Query / Task**: Execute initial SQL schema migrations and security triggers against the database adapter.
- **Result / Model Output**: Generated code called `rawClient.query(migrationSql)` with multi-statement SQL strings containing table definitions, indexes, and trigger functions.
- **Discrepancy / Weakness**: PGlite treats `.query()` as a prepared statement, which rejects multiple semicolons and transaction blocks with `syntax error at or near ";"`.
- **Resolution**: Refactored `runMigrations()` in `src/server/db/migrate.ts` to branch on `'exec' in rawClient` using `.exec()` for multi-statement scripts.
- **Commit Reference**: `d788f84`

### [2026-10-24 18:35] - Phase 3: Magic-Byte Sniffing on Zip Containers (DOCX, XLSX, PPTX)
- **Query / Task**: Implement upload file validation for DOCX, XLSX, and PPTX office documents.
- **Result / Model Output**: Matched only initial 4 bytes `PK\x03\x04`.
- **Discrepancy / Weakness**: Any generic zip archive or executable disguised as a zip would match `PK\x03\x04` and bypass type checks.
- **Resolution**: Extended `detectMagicBytes()` in `src/server/validation/upload.ts` to inspect inner directory markers (`word/`, `xl/`, `ppt/`) in the first 2 KB.
- **Commit Reference**: `14b1e23`

### [2026-10-24 19:15] - Phase 9: Adversarial Attack Pass Parameter Mismatch
- **Query / Task**: Run attack pass test validating upload buffer rejection on empty payloads.
- **Result / Model Output**: Called `validateUploadedFile(emptyBuffer, 'empty.pdf')` with 2 arguments instead of 3.
- **Discrepancy / Weakness**: TypeScript compiler threw TS2554 expecting `declaredSize: number` as the third parameter.
- **Resolution**: Aligned all call sites to pass `(buffer, fileName, buffer.length)`.
- **Commit Reference**: `9068285`

### [2026-10-25 11:45] - Priority 1: In-Flight Revocation on Active Chunk Streams
- **Query / Task**: Re-evaluate authorization and grants dynamically while streaming files to prevent revoked users from receiving the remainder of an in-flight file.
- **Result / Model Output**: Returned a single full buffer via `new NextResponse(new Uint8Array(responseBuffer))` that could not detect revocations that happen after transmission starts.
- **Discrepancy / Weakness**: Once the HTTP response was dispatched, an owner revoking access could not stop an in-flight download of a large file on a slow link.
- **Resolution**: Converted file streaming in `src/app/api/documents/[id]/download/route.ts` to a chunked `ReadableStream` with 64 KB chunk boundaries. On each chunk boundary after chunk 0, it calls `validateSession()` and `can(user, 'download', doc)`. If revoked mid-stream, it aborts via `controller.error()` and logs `IN_FLIGHT_REVOCATION_ABORTED`. Tested in `tests/security/in-flight-revocation.test.ts`.
- **Commit Reference**: `c414f5e`

### [2026-10-25 12:00] - Priority 1: Timing Leak Between Missing and Forbidden Documents
- **Query / Task**: Ensure non-existent documents and forbidden documents return uniform 404 responses with zero timing differentiation.
- **Result / Model Output**: Threw `UniformNotFoundOrForbiddenError` immediately when `docs.length === 0`, skipping the `document_grants` table query and `can()` CPU policy evaluation that occur when an existing document is evaluated.
- **Discrepancy / Weakness**: Missing document requests returned in ~1-2ms, while forbidden existing document requests returned in ~5-6ms, creating a timing side-channel that leaks document existence to an attacker.
- **Resolution**: Equalized execution in `getDocumentWithAuthorization()` (`src/server/services/documents.ts`) by executing a dummy grant table query and dummy `can()` policy evaluation on missing IDs before throwing `UniformNotFoundOrForbiddenError`. Benchmarked in `tests/security/timing.test.ts` where timing difference is reduced to under 1.5ms (delta 0.02ms - 1.01ms).
- **Commit Reference**: `c414f5e`

### [2026-10-25 12:14] - Priority 2: Forensic Document Access Audit Querying
- **Query / Task**: Allow an administrator to answer "who opened document X and when?" directly in the UI with one query without paging through all global logs.
- **Result / Model Output**: `GET /api/admin/audit` only supported filtering by `action`, `outcome`, and `actor`, requiring administrators to page through global logs to correlate events for a specific document ID.
- **Discrepancy / Weakness**: Sifting through thousands of global audit events to find accesses for a specific compromised document is error-prone and slow during incident response.
- **Resolution**: Added first-class `documentId` query parameter support in `src/app/api/admin/audit/route.ts` and added a dedicated Document ID filter input to the Admin Global Audit Explorer UI (`src/app/(dashboard)/admin/audit/page.tsx`). Tested in `tests/security/db-privileges.test.ts`.
- **Commit Reference**: `f200c30`

---

## Phase Review & Architecture Decisions

### Phase 1: Foundation
- **Uncertainty / Review Areas**:
  - Multi-statement execution: Discovered `pglite.query()` treats strings as prepared statements rejecting multi-statement migrations; resolved by branching to `pglite.exec()` for bulk schema migration.
  - Ensuring the database connection pool supports advisory locks (`pg_advisory_xact_lock`) without connection leakage across transactions.
  - Verification: Schema and triggers strictly enforce append-only constraints both in development (PGlite) and production (Postgres).

### Phase 2: Auth and Roles
- **Uncertainty / Review Areas**:
  - **Admin Content Exclusion vs Admin Audit Viewing**: We explicitly denied `can(adminUser, 'view', doc)` and `can(adminUser, 'download', doc)` unless explicitly granted. However, the Admin *must* view audit log entries that contain metadata (doc title, doc id) in `/api/admin/audit`. We ensured the audit explorer queries the `audit_logs` table directly with admin role checks, while the document streaming/metadata routes strictly call `can()`.
  - **Account Lockout Timing Leak**: If an attacker attempts to guess emails, responding with 423 Locked reveals the account exists. We ensured that unknown accounts never return 423, but to avoid timing discrepancies, Argon2 dummy verification is evaluated when a user is not found.
  - **Immediate Invalidation on User Disablement**: `validateSession()` queries `users.isDisabled` on every request. If true, it deletes all user sessions from the DB immediately and aborts the request with 401.

### Phase 3: Documents and Storage
- **Uncertainty / Review Areas**:
  - **Magic-Byte Sniffing on Zip Containers (DOCX, XLSX, PPTX)**: Office documents share the same PK Zip container header (`PK\x03\x04`). We inspect the initial 2KB payload for specific folder markers (`word/`, `xl/`, `ppt/`) to prevent attackers from smuggling malicious zip archives as documents.
  - **Streaming File Downloads with Fresh Policy Check**: Instead of issuing signed S3 URLs (which cannot be revoked until expiry), files are proxied through `/api/documents/[id]/download`. Every download query evaluates `validateSession()` and `getDocumentWithAuthorization(..., 'download')` on the exact millisecond before reading disk bytes.
  - **SQL-Level Authorization Filtering**: We ensured `listAuthorizedDocuments` and `/api/search` execute the grant check directly in the SQL `WHERE` clause (`WHERE owner_id = :uid OR id IN (SELECT document_id FROM document_grants ...)`), preventing memory exhaustion or data leakage from client-side filtering.

### Phase 4: Sharing and Immediate Revocation
- **Uncertainty / Review Areas**:
  - **Zero-Latency Invalidation**: By avoiding signed URLs or bearer download tokens, every stream and range request requires an active DB grant lookup. The trade-off is higher database read load during high-concurrency downloads, but it guarantees that revoked grants terminate instantaneously without any cache TTL lag.
  - **Owner Self-Grant Prevention**: Checked that an owner cannot grant permissions to themselves, avoiding duplicate or conflicting ACL records.
  - **User Disablement Cascade**: Disabling a user immediately executes `revokeAllUserSessions()`, destroying their active sessions and denying any subsequent API call with 401.

### Phase 5: Tamper-Evident Audit Trail
- **Uncertainty / Review Areas**:
  - **Advisory Locks under Concurrent Inserts**: Audit chain hashing requires strict sequencing (`SHA-256(prev_hash + canonical_json)`). We use `pg_advisory_xact_lock(424242)` inside the transaction so concurrent writers line up in single file and never branch the hash chain.
  - **Canonical JSON Representation**: Because object key ordering in JavaScript can vary, we built `canonicalJsonStringify()` which sorts keys alphabetically and strips undefined properties, ensuring identical SHA-256 digests across Node.js versions and platforms.
  - **Atomic Failure Handling**: If an audit record fails to insert, `logAuditEvent` throws an unhandled operational exception to ensure the sensitive action (download, upload, grant) is aborted rather than silently succeeding without audit evidence.

### Phase 6: Admin Capabilities & Security Alerts
- **Uncertainty / Review Areas**:
  - **Admin Content Isolation Defense**: Re-verified that `/api/documents/[id]/download` invokes `can(adminUser, 'download', doc)`. Since `can()` rejects admin role unless an explicit row exists in `document_grants`, Admin receives a 404 response if attempting direct file exfiltration.
  - **Security Alerts Thresholds**: Implemented 5 clear, deterministic thresholds for "worth noticing" events: denied spikes ($\ge 3$ in 15 mins), odd hours (00:00-05:00 UTC), bulk downloads ($\ge 5$ in 10 mins), account lockouts, and revoked-user probes.
  - **CSV Export Escaping**: In the `/api/admin/audit?format=csv` stream, all fields are double-quoted and inner quotes are escaped (`""`) to prevent CSV injection / formula execution vulnerabilities.

### Phase 7: AI Sharing Suggestions
- **Uncertainty / Review Areas**:
  - **Strict Content Decoupling**: Ensured the suggestion service receives only `{ category, ownerId }` metadata. It has zero access to storage keys, disk buffers, or document text contents.
  - **Confirm-Only UX Boundary**: The suggestions endpoint strictly returns candidate recommendation objects to pre-fill client form fields. Under no circumstance does the suggestion route insert into `document_grants`. This was explicitly proved in `tests/security/ai-suggestions.test.ts`.
  - **Auditing Advisory Interactions**: Added dedicated audit actions `SUGGESTION_SHOWN`, `SUGGESTION_ACCEPTED`, and `SUGGESTION_REJECTED` so auditors can track algorithmic suggestions and human confirmations.

### Phase 8: Landing Page & App UI
- **Uncertainty / Review Areas**:
  - **Industrial Identity Consistency**: Ensured exact design token adherence (`--ink: #0B1220`, `--paper: #F0EFEA`, `--accent: #FF5A1F`, `--denied: #E5484D`, `--allowed: #30A46C`). All eyebrows use the small orange square bullet (`■`).
  - **Card 03 Highlight in Solid Orange**: In the landing page "Three promises", card 03 ("Revoking works immediately") is prominently rendered with a solid orange background and white high-contrast typography as requested.
  - **Live Access Simulation Fidelity**: Ensured the "Try to break it" widget and Live Access Log card show realistic SHA-256 blocks, true policy decision rationale, and explicit simulation labels.
  - **Uniform 404 UI**: Document detail routes and the custom Next.js 404 page emit identical layouts for both missing and forbidden documents.
