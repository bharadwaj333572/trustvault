# TrustVault Security-Critical Code Review Checklist

> **Auditor Guidance**: This document enumerates all security-critical files in the TrustVault architecture. Each component must be inspected by a human security auditor against the specified invariants.

---

## 1. Central Policy Engine

**File**: [`src/server/policy/index.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/policy/index.ts)  
**Primary Invariants**:
- Sole authorization chokepoint across all API routes, server actions, and file downloads.
- Default is strictly `DENY`.
- Disabled accounts (`isDisabled = true`) rejected immediately.
- Soft-deleted documents blocked from non-owners.
- Admin content isolation: Admin CANNOT view or download contents without explicit grant.
- Expired grants (`expiresAt <= now`) denied access.

### Human Auditor Checklist
- [ ] **Static Code Review**: Confirm pure function signature without external I/O side effects.
- [ ] **Default DENY Verification**: Confirm no code branch returns `allowed: true` without matching a valid rule.
- [ ] **Admin Isolation Verification**: Confirm `user.role === 'ADMIN'` branch returns `allowed: false`.
- [ ] **Mutation Testing Review**: Confirm all 8 policy mutants in [`docs/MUTATION_RESULTS.md`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/docs/MUTATION_RESULTS.md) were killed.
- **Auditor Notes / Findings**: _________________________________________________
- **Sign-off**: `[ ] APPROVED   [ ] REJECTED` | **Date**: _______________

---

## 2. File Streaming & Immediate Revocation

**File**: [`src/app/api/documents/[id]/download/route.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/app/api/documents/[id]/download/route.ts)  
**Primary Invariants**:
- Zero pre-signed URLs or long-lived bearer download tokens.
- Fresh database session lookup on EVERY request (`validateSession`).
- Fresh central policy check immediately before reading disk storage keys (`getDocumentWithAuthorization`).
- Serves with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
- Range requests (`Range: bytes=...`) must execute authorization check before byte slicing.

### Human Auditor Checklist
- [ ] **Revocation Latency**: Verify that revoking a grant causes the very next download to return 404.
- [ ] **Range Request Verification**: Verify range requests cannot bypass authorization.
- [ ] **Content-Disposition Inspection**: Verify filenames cannot execute inline XSS in browsers.
- **Auditor Notes / Findings**: _________________________________________________
- **Sign-off**: `[ ] APPROVED   [ ] REJECTED` | **Date**: _______________

---

## 3. Cryptographic Audit Trail & Checkpoint Anchoring

**File**: [`src/server/services/audit.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/services/audit.ts)  
**Primary Invariants**:
- SHA-256 hash chaining: $hash_n = \text{SHA-256}(prev\_hash_{n-1} + \text{canonical\_json}(row_n))$.
- Canonical JSON key sorting prevents cross-platform hash divergence.
- Strict serialization under concurrency via FIFO async mutex (`acquireChainLock`) and PostgreSQL advisory locks.
- Signed checkpoints (`chain_checkpoints`) detect tail row deletion (`TRUNCATED: expected #n, found #m`).
- Sanitization of user-controlled metadata prevents CRLF log injection.

### Human Auditor Checklist
- [ ] **Trigger Tamper Resistance**: Attempt direct `UPDATE` / `DELETE` via SQL and verify exception.
- [ ] **Tail Truncation Simulation**: Delete highest sequence row and verify `verifyChain()` detects gap.
- [ ] **Concurrency Stress Review**: Verify 50 parallel writes produce continuous valid hash chain.
- [ ] **Log Injection Verification**: Confirm newlines in filenames/titles are stripped.
- **Auditor Notes / Findings**: _________________________________________________
- **Sign-off**: `[ ] APPROVED   [ ] REJECTED` | **Date**: _______________

---

## 4. Grant Management & Revocation Path

**File**: [`src/server/services/grants.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/services/grants.ts)  
**Primary Invariants**:
- Only document OWNER has permission to grant or revoke access.
- Non-existent user emails rejected with 400 Validation Error.
- Disabled user accounts rejected with 400 Validation Error.
- Self-grants rejected with 400 Validation Error.
- Grant deletion takes effect immediately without caching delays.

### Human Auditor Checklist
- [ ] **Self-Grant Prevention**: Verify owner cannot create ACLs granting themselves access.
- [ ] **Disabled Target Prevention**: Verify grants cannot be assigned to suspended accounts.
- [ ] **Non-Owner Granting Prevention**: Verify EDIT-granted users cannot share documents.
- **Auditor Notes / Findings**: _________________________________________________
- **Sign-off**: `[ ] APPROVED   [ ] REJECTED` | **Date**: _______________

---

## 5. Upload Validation & Polyglot Defense

**File**: [`src/server/validation/upload.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/validation/upload.ts)  
**Primary Invariants**:
- Magic byte sniffing (first 512 bytes) ignores client-claimed Content-Type and extension.
- Strictly allows: PDF (`%PDF`), PNG (`\x89PNG`), JPEG, Office OpenXML (ZIP + content check), CSV, TXT.
- Executables (PE `MZ`, ELF) and active content (HTML, SVG) strictly rejected.
- Zero-byte files rejected.
- Path traversal sequences (`../`, `..\`, null bytes) sanitized from filenames.

### Human Auditor Checklist
- [ ] **Executable Polyglot Test**: Verify PE binary disguised with `.pdf` extension is blocked.
- [ ] **Stored XSS Test**: Verify HTML payload disguised with `.docx` extension is blocked.
- [ ] **Path Traversal Test**: Verify `../../etc/passwd` filename is stripped to safe base name.
- **Auditor Notes / Findings**: _________________________________________________
- **Sign-off**: `[ ] APPROVED   [ ] REJECTED` | **Date**: _______________

---

## 6. Session Handling & Multi-Device Purge

**File**: [`src/server/auth/session.ts`](file:///C:/Users/chintu/.gemini/antigravity/scratch/trustvault/src/server/auth/session.ts)  
**Primary Invariants**:
- DB-backed sessions with high-entropy random 256-bit opaque tokens.
- Tokens stored SHA-256 hashed in database; raw token in `HttpOnly`, `SameSite=Lax`, `Secure` cookie.
- Account disablement immediately executes `revokeAllUserSessions()` to purge all sessions across devices.
- Account lockout after 5 consecutive failed logins (15-minute lockout).

### Human Auditor Checklist
- [ ] **Multi-Device Purge**: Verify disabling user immediately invalidates sessions in other browsers.
- [ ] **Session Invalidation on Logout**: Verify logout deletes database session row.
- [ ] **Brute-Force Lockout**: Verify 5 invalid login attempts lock account for 15 minutes.
- **Auditor Notes / Findings**: _________________________________________________
- **Sign-off**: `[ ] APPROVED   [ ] REJECTED` | **Date**: _______________
