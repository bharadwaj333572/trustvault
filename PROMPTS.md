# TrustVault — Prompts & Human Review Log

This document records prompts, unexpected model outputs, discrepancies, and areas of uncertainty regarding authorization and audit trail integrity. Entries are logged strictly during development when real events occur.

---

## Log Template

```markdown
### [YYYY-MM-DD HH:MM] - Phase <Phase Number>: <Phase Name>
- **Query / Task**: What was asked or instructed.
- **Result / Model Output**: What was generated or proposed.
- **Discrepancy / Weakness**: What was incorrect, insecure, or ambiguous.
- **Resolution**: What was implemented instead and why.
- **Commit Reference**: `<commit hash>`
```

---

## Phase Review & Areas of Uncertainty

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

---

### Phase 9: Adversarial Attack Pass & Mutation Checking
- **Uncertainty / Review Areas**:
  - **Mutation Testing Verification**: Built `scripts/mutation-check.ts` to simulate an attacker bypassing the policy check by flipping the default DENY rule to `return { allowed: true }`. Confirmed our test suite caught the mutation immediately and aborted with exit code 1.
  - **Uniform 404 Timing and Payload Shape**: Validated that `UniformNotFoundOrForbiddenError` produces byte-for-byte identical HTTP 404 responses for non-existent document IDs vs existing document IDs where the actor lacks permission, eliminating timing and status enumeration attacks.
  - **Mass Assignment Defenses**: Tested that client payloads sending `ownerId`, `isDeleted`, or `userId` in `POST /api/documents` or `PATCH /api/documents/[id]` are completely discarded by the server handlers.
  - **Admin Content Isolation**: Confirmed via dedicated adversarial attack tests that Admin accounts attempting to invoke download or view on documents owned by others receive 404 Not Found.
  - **Audit Completeness**: Verified that all failed/denied requests trigger a synchronous insert into `audit_logs` with `outcome: 'DENIED'` and `action: 'DENIED_ATTEMPT'`.

### Phase 10: Documentation, Packaging & Production Readiness
- **Uncertainty / Review Areas**:
  - **Zero-Config Clean Clone**: Tested that cloning the repository and running `npm install && npx tsx scripts/seed.ts && npm run dev` works with zero prerequisites or external database configuration due to embedded PGlite.
  - **Audit Trigger Portability**: Verified that while PGlite in WebAssembly/Node executes standard PostgreSQL `BEFORE UPDATE/DELETE` triggers, production deployments on standard PostgreSQL services (Render, Railway, Fly.io) will execute the identical triggers without modification.
  - **Honest Limitations Disclosure**: Documented known trade-offs in `README.md`, including the deliberate choice against complex group permissions and folder inheritance, absence of MFA, and lack of WebSocket pushes for revocations.
