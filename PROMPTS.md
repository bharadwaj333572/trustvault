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

---
