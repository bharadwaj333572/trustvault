# TrustVault — Security & Authorization Review Queue

This queue documents every area in the authorization, audit, or session engine where subtle edge cases, architectural trade-offs, or potential timing/concurrency nuances warrant human security auditor review.

---

## Review Queue Entries

### 1. In-Process vs Clustered Advisory Locking
- **File**: [`src/server/services/audit.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/services/audit.ts)
- **Context**: SHA-256 hash chaining requires strict serialization ($hash_n = \text{SHA256}(prev\_hash_{n-1} + \text{canonical}(row_n))$).
- **Nuance**: In embedded PGlite or single-node Next.js instances, an in-process serialization lock (async mutex) guarantees perfect sequential ordering. In a multi-replica clustered deployment with a central PostgreSQL database, `pg_advisory_xact_lock` must be acquired inside an active transaction. We provide both the database-level advisory lock query and in-process mutex fallback.
- **Review Question**: In multi-region deployments, should audit writes queue through a single dedicated write worker or Redis lock?

### 2. Tail Truncation & External Anchoring
- **File**: [`src/server/services/audit.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/services/audit.ts)
- **Context**: If an adversary obtains root database access, they can delete the newest rows $N, N-1$ without breaking the hash integrity of remaining rows $1 \dots N-2$.
- **Nuance**: We implemented a `chain_checkpoints` table with HMAC signatures (`AUDIT_HMAC_SECRET`) and comparison against the latest checkpoint sequence number. If live rows are missing, `verifyChain()` flags `TRUNCATED: expected #n, found #m`. An export endpoint allows saving checkpoints to external WORM storage.
- **Review Question**: Is the periodic checkpoint interval (every 10 events) appropriate for your audit log volume, or should every admin session trigger an automatic external webhook export?

### 3. Immediate Revocation vs Streaming Chunks
- **File**: [`src/server/services/documents.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/services/documents.ts), [`src/app/api/documents/[id]/download/route.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/app/api/documents/[id]/download/route.ts)
- **Context**: Authorization is checked synchronously immediately before streaming begins.
- **Nuance**: For small to medium files (< 25 MB), streaming completes in under 1-2 seconds. For large multi-megabyte streams over slow connections, if a grant is revoked halfway through an in-flight connection, the stream has already started. We evaluate whether per-chunk boundary re-validation is justified against database query amplification.
- **Decision**: 25 MB max file size ensures in-flight downloads complete near-instantaneously. Re-validation occurs on every single request, range request, and version download.

### 4. Privilege Separation: DB Triggers vs DB Superusers
- **File**: [`src/server/db/migrate.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/db/migrate.ts)
- **Context**: PostgreSQL `BEFORE UPDATE OR DELETE` triggers raise exceptions on audit table mutation.
- **Nuance**: A PostgreSQL superuser (`postgres`) can issue `ALTER TABLE audit_logs DISABLE TRIGGER ALL;`. PostgreSQL trigger protection is designed for the application database role (`trustvault_app`). Defense-in-depth against superuser tampering is provided by the HMAC-signed external anchor.
