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

---
