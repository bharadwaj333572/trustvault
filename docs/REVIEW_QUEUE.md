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
- **Context**: Authorization is checked synchronously on download route entry and re-checked at every chunk boundary during streaming.
- **Implementation**: The download route streams file buffers through a `ReadableStream` divided into 64 KB chunks. On each chunk boundary after chunk 0, the engine performs a fresh `validateSession(token)` and `can(user, 'download', doc)` evaluation. If access was revoked mid-stream, the stream calls `controller.error()`, logs `IN_FLIGHT_REVOCATION_ABORTED` in the audit chain, and tears down the connection.
- **Window**: The maximum in-flight exposure window is bounded by exactly 1 chunk (up to 64 KB) already transmitted to the client socket buffers.
- **Review Question**: Is the 64 KB chunk check window acceptable for your bandwidth environment, or should chunk sizes adapt to client latency?

### 4. Privilege Separation: DB Triggers vs DB Superusers
- **File**: [`src/server/db/migrate.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/db/migrate.ts)
- **Context**: PostgreSQL `BEFORE UPDATE OR DELETE` triggers raise exceptions on audit table mutation.
- **Nuance**: A PostgreSQL superuser (`postgres`) can issue `ALTER TABLE audit_logs DISABLE TRIGGER ALL;`. PostgreSQL trigger protection is designed for the application database role (`trustvault_app`). Defense-in-depth against superuser tampering is provided by the HMAC-signed external anchor.

### 5. Timing Equalization on Document Lookup
- **File**: [`src/server/services/documents.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/services/documents.ts)
- **Context**: Timing side-channels can leak document existence if missing IDs return faster than existing IDs (where grants are queried and evaluated).
- **Implementation**: In `getDocumentWithAuthorization()`, when `docs.length === 0` (missing document), the code executes a dummy query against `document_grants` and a dummy `can()` policy evaluation before logging the denied audit event and throwing `UniformNotFoundOrForbiddenError`.
- **Benchmark**: Verified in `tests/security/timing.test.ts` where the mean latency difference between missing and forbidden is under 1.5ms (delta ~0.02ms - 1.01ms).

### 6. Session Lifecycle & Invalidation Matrix
- **File**: [`src/server/auth/session.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/auth/session.ts), [`src/app/api/auth/login/route.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/app/api/auth/login/route.ts), [`src/app/api/admin/users/[id]/route.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/app/api/admin/users/[id]/route.ts)
- **Implementation**:
  - **Login Rotation**: Replaces previous session token in cookies on every successful login.
  - **Disable User**: Purges all sessions in the DB immediately.
  - **Role Change**: Purges all sessions immediately so demoted or modified users cannot use old tokens.
  - **Password Change**: Purges all sessions and creates a single fresh session.
  - **Sign Out Other Devices**: Deletes all sessions except the active `sessionId`.
  - **Timeouts**: Absolute timeout of 7 days (`SESSION_TTL_SECONDS`) and idle inactivity timeout of 4 hours (`SESSION_IDLE_TIMEOUT_SECONDS`) based on `last_active_at`.

### 7. Owner Transfer Inadmissibility
- **File**: [`src/app/api/documents/[id]/route.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/app/api/documents/[id]/route.ts)
- **Implementation**: Document ownership is strictly immutable from creation. The `PATCH` endpoint enforces strict mass-assignment allowlists (`title`, `category`, `folderPath`) and explicitly ignores any attempts to change `ownerId` or `isDeleted`. Documented as unsupported by design in `docs/ROLES.md` and `docs/THREATS.md`.

### 8. Upload Polyglot & Magic-Byte Enforcement
- **File**: [`src/server/validation/upload.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/validation/upload.ts)
- **Implementation**:
  - Analyzes true magic bytes (PDF `%PDF-`, PNG `\x89PNG`, JPEG `\xFF\xD8\xFF`, Zip/Office `PK\x03\x04`).
  - Matches declared file extension against detected binary MIME type. Mismatched extensions (e.g. `.pdf` containing PNG or script) are rejected as polyglot attempts.
  - Disallows executable extensions (`.exe`, `.dll`, `.sh`, `.bat`, etc.) and formats (PE `MZ`, ELF `\x7fELF`).
  - Includes malware scan integration hook (`scanFileForMalware`).
