# TrustVault Agentic Engineering Rules & Architecture Invariants

> **Auditor Guidance**: This document details the operating rules, context prompts, and behavioral invariants governing AI agent assistance during the development, hardening, and review of TrustVault.

---

## 1. Core Operating Invariants

1. **Adversarial Security First**: Correctness of authorization and tamper-evident auditability supersedes feature count. The application is evaluated by an adversary actively attempting to reach ungranted documents.
2. **Sole Authorization Chokepoint**: Every route handler, server action, list query, search query, and file stream must pass through `can(user, action, document, grants)` in `src/server/policy/index.ts`. No scattered role or permission checks.
3. **Default DENY**: Default return of every policy evaluation is `DENY`. Any ungranted or unrecognized permission state is blocked.
4. **Immediate Revocation**: No signed URLs or long-lived bearer download tokens. Downloads stream through the API after a real-time policy check on every single request.
5. **Admin Content Isolation**: The `ADMIN` role manages users, views global audit telemetry, and configures security alerts. Admins possess **zero implicit read/download permissions** on documents unless granted like any other user.
6. **SQL-Level Authorization Filtering**: Search and list queries must filter by ownership and active grants directly inside SQL predicates (`WHERE owner_id = :uid OR id IN (SELECT document_id FROM document_grants ...)`), never post-fetch in application memory.
7. **Append-Only Tamper-Evident Audit Chain**: Every sensitive action and every denied access attempt must write a row to `audit_logs`. The table is protected by PostgreSQL `BEFORE UPDATE/DELETE` triggers that raise exceptions upon mutation. Rows are chained via `hash = SHA256(prev_hash + canonical_json(row))`.
8. **Never Trust Client-Sent Ownership**: Ignore `ownerId`, `userId`, `role`, or `isDeleted` in request bodies. Always bind ownership strictly to the validated database session.
9. **Zero-Existence Disclosure**: Unauthorized document queries return the exact same HTTP 404 `NOT_FOUND` status and error payload shape as non-existent UUIDs.
10. **Safe AI Suggestions**: Algorithmic suggestions operate solely on metadata co-occurrence. Zero document text or bytes are exposed to language models. Suggestions alone grant zero access; an authenticated human must confirm every grant.

---

## 2. Testing & Verification Rules

- **Conventional Commits**: Every phase and logical change must be recorded in small, conventional git commits (`feat:`, `security:`, `fix:`, `test:`, `docs:`). Squashing is prohibited.
- **Run Before Claiming**: An agent must never claim code works without running automated tests (`npm test` / `npx vitest run`).
- **Mutation Testing Requirement**: When adding or updating authorization rules, run `npx tsx scripts/mutation-check.ts` to ensure the mutation test suite catches intentionally disabled policy rules.
- **Audit Verification**: Run `npx tsx scripts/verify-audit-chain.ts` to confirm cryptographic integrity across all blocks.
- **Prompts & Review Integrity**: Never fabricate post-mortem prompt entries. Use `scripts/check-prompt-entries.ts` to track real discrepancies and review queues.
