# TrustVault Threat Model & Adversarial Defense Matrix (30 Vectors)

> **Document Status**: Production Defense-in-Depth Specification  
> **Last Verified**: Phases A & B Security Hardening & Mutation Testing  
> **Verification Status**: 100% Mitigated & Verified across Unit, Integration, and Security Test Suites.

TrustVault operates under an adversarial security premise: **the system is evaluated by actors actively seeking to access, tamper with, or exfiltrate documents they were never granted.**

Below is the exhaustive matrix of all 30 identified threat vectors, exploit paths, architectural mitigations, and automated tests.

---

## 1. Adversarial Threat Matrix (30 Vectors)

| Threat ID | Threat Category | Threat Description | Exploit Path | Architectural Mitigation | Status | Verified Test File |
|:---|:---|:---|:---|:---|:---:|:---|
| **T-01** | Authorization | **IDOR on Document Access** | Non-granted user attempts to fetch or download documents by guessing UUIDs. | Central `can(user, action, doc)` authorization chokepoint filters every access. Returns uniform 404 shape with zero existence leakage. | **MITIGATED** | `tests/security/attack-pass.test.ts` |
| **T-02** | Privilege Escalation | **Viewer Role Upload / Modification** | Viewer role attempts to POST upload or edit document contents. | Upload endpoint strictly blocks non-OWNER roles with 403 Forbidden. Editor role checks enforce owner-only modification rights. | **MITIGATED** | `tests/security/attack-pass.test.ts` |
| **T-03** | Injection / Tamper | **Mass Assignment in Payloads** | Attacker submits `ownerId`, `isDeleted`, or `role` fields in HTTP request bodies. | Handlers explicitly pluck safe fields only (`title`, `category`, `folderPath`). `ownerId` is strictly derived from validated session. | **MITIGATED** | `tests/security/attack-pass.test.ts` |
| **T-04** | Access Boundary | **Admin Content Snooping** | System Administrator attempts to view or download document contents without a grant. | Architectural isolation: Admin role only has metadata and system audit privileges. `can()` returns `DENIED` for Admin file downloads. | **MITIGATED** | `tests/integration/admin.test.ts` |
| **T-05** | Audit Integrity | **Audit Row Tampering / Deletion** | Malicious insider or DB connection executes `UPDATE` or `DELETE` on audit table. | PostgreSQL `BEFORE UPDATE OR DELETE` database triggers raise immutable exceptions, permanently locking rows upon INSERT. | **MITIGATED** | `tests/security/audit.test.ts` |
| **T-06** | Audit Integrity | **Audit Row Injection / Reordering** | Attacker inserts out-of-band audit rows or scrambles chronological sequence. | Cryptographic SHA-256 hash chain: `hash = SHA256(prev_hash + canonical_json(row))`. Advisory lock ensures strict serial ordering. | **MITIGATED** | `tests/security/audit.test.ts` |
| **T-07** | Authorization | **Grant Expiry Bypass** | User attempts to access a document using an expired grant. | Active grant filters evaluate `expiresAt > NOW()` at both SQL query level and runtime `can()` policy evaluation. | **MITIGATED** | `tests/security/attack-pass.test.ts` |
| **T-08** | Authorization | **Revocation Race Window / Signed URLs** | Attacker uses a pre-generated signed S3 URL or token after access has been revoked. | Zero signed URLs. All file payloads stream through `/api/documents/[id]/download` requiring real-time DB policy evaluation per byte stream. | **MITIGATED** | `tests/security/immediate-revocation.test.ts` |
| **T-09** | File Validation | **MIME-Type / Extension Spoofing** | Attacker disguises an executable file by renaming it to `.pdf` or spoofing Content-Type. | Server-side magic byte sniffing inspects first 512 bytes against strict binary signatures (PDF `%PDF`, PNG `\x89PNG`, JPEG, Office ZIP). | **MITIGATED** | `tests/integration/documents.test.ts` |
| **T-10** | File Validation | **Executable Binary Upload** | Attacker uploads Windows PE (.exe) or Linux ELF binaries to the storage backend. | Validation rejects PE (`MZ`), ELF (`\x7fELF`), and script files instantly regardless of client claims or file extension. | **MITIGATED** | `tests/integration/documents.test.ts` |
| **T-11** | File Validation | **Path Traversal in Filename** | Upload filename includes `../../etc/passwd` or `..\system32` to escape storage root. | Filenames are stripped of path delimiters and stored under randomized UUID storage keys (`storage/files/<uuid>`). Real name is display-only. | **MITIGATED** | `tests/integration/documents.test.ts` |
| **T-12** | Session Security | **Session Fixation / Replay** | Attacker captures or predicts session identifiers to hijack an active user session. | High-entropy crypto-random tokens (128-bit) stored SHA-256 hashed in database. Session regenerated upon login; deleted upon logout. | **MITIGATED** | `tests/integration/auth.test.ts` |
| **T-13** | Authentication | **Brute Force Credential Guessing** | Attacker attempts automated password dictionary attacks against login route. | IP-based sliding window rate limiter plus progressive account lockout (5 failed attempts = 15-minute account lock). | **MITIGATED** | `tests/integration/auth.test.ts` |
| **T-14** | Request Forgery | **Cross-Site Request Forgery (CSRF)** | Third-party malicious website submits unauthorized state changes on behalf of logged-in user. | SameSite=Lax cookie attribute combined with strict `Origin` and `Host` header validation on mutating requests in middleware. | **MITIGATED** | `tests/integration/auth.test.ts` |
| **T-15** | Data Leakage | **Cross-Tenant Search Query Leakage** | Search terms or document counts disclose existence of documents owned by other tenants. | Search endpoint enforces SQL-level join against user ownership and active grants before aggregation, pagination, or scoring. | **MITIGATED** | `tests/security/attack-pass.test.ts` |
| **T-16** | Client-Side XSS | **Stored XSS via Rendered HTML/SVG** | Attacker uploads malicious HTML or SVG that executes scripts in victim's browser session. | HTML and SVG formats rejected at upload. Downloads served with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. | **MITIGATED** | `tests/integration/documents.test.ts` |
| **T-17** | AI Safety | **Autonomous Access Widening by AI** | Machine learning suggestion engine widens document permissions automatically. | Suggestion engine is strictly collaborative; human confirmation required for all grants. Zero document text sent to suggestions model. | **MITIGATED** | `tests/security/ai-suggestions.test.ts` |
| **T-18** | Observability | **Silent Denial / Unlogged Probing** | Attacker scans for endpoints or document IDs without generating an audit trail. | Every authorization failure triggers synchronous `logAuditEvent(action: 'DENIED_ATTEMPT')` recording actor, IP, timestamp, and true reason. | **MITIGATED** | `tests/security/attack-pass.test.ts` |
| **T-19** | Information Disclosure | **Existence Leakage via Timing / Status** | Attacker differentiates between non-existent files and unauthorized files. | Both missing documents and forbidden access return identical HTTP 404 `NOT_FOUND` payloads with uniform message shapes. | **MITIGATED** | `tests/security/attack-pass.test.ts` |
| **T-20** | Injection | **SQL Injection in Query / Filter Engine** | Malicious characters in search queries or filters manipulate database queries. | 100% parameterised SQL queries through Drizzle ORM and prepared statements. String concatenation in queries is strictly prohibited. | **MITIGATED** | `tests/integration/documents.test.ts` |
| **T-21** | Audit Integrity | **Audit Tail Truncation** | Attacker deletes the latest $N$ rows; remaining chain $1 \dots N-k$ appears valid. | Signed checkpoints (`chain_checkpoints`) with HMAC-SHA256; `verifyChain()` detects sequence number gap (`TRUNCATED: expected #n, found #m`). | **MITIGATED** | `tests/security/audit-hardening.test.ts` |
| **T-22** | Enumeration | **User Autocomplete Scraping** | Attacker uses character-by-character search queries to scrape internal employee list. | Minimum query length of 3 chars required; rate limited (30 req/min); response limited to 5 results; password/security fields excluded. | **MITIGATED** | `tests/security/auth-edge-cases.test.ts` |
| **T-23** | Privilege Escalation | **Admin Elevation via Body Manipulation** | Attacker crafts user update request to elevate their account to `ADMIN`. | `PATCH /api/admin/users/[id]` strictly guarded by `user.role === 'ADMIN'`. Regular users have no access to user update routes. | **MITIGATED** | `tests/integration/admin.test.ts` |
| **T-24** | Session Management | **Multi-Device Session Persistence** | Suspended user continues accessing documents via active sessions on other devices. | Disabling user account executes `revokeAllUserSessions()`, deleting all DB sessions for that user across all devices immediately. | **MITIGATED** | `tests/security/auth-edge-cases.test.ts` |
| **T-25** | Authorization | **Version Download Authorization Bypass** | Revoked user tries to access document historical versions via version download query. | `/api/documents/[id]/download?version=n` invokes central `can(user, 'download', doc)` on every request before resolving storage keys. | **MITIGATED** | `tests/security/auth-edge-cases.test.ts` |
| **T-26** | Authorization | **HTTP Range Request Exfiltration** | Attacker crafts `Range: bytes=0-100` headers to bypass complete download authorization checks. | Range requests pass through the exact same central `can()` authorization chokepoint before byte slicing occurs. | **MITIGATED** | `tests/security/auth-edge-cases.test.ts` |
| **T-27** | Information Disclosure | **Soft-Delete Document Snooping** | Attacker probes soft-deleted document UUIDs to ascertain metadata or title. | Central policy treats soft-deleted documents as inaccessible to all non-owners, returning uniform 404 without existence disclosure. | **MITIGATED** | `tests/security/auth-edge-cases.test.ts` |
| **T-28** | Concurrency | **Concurrent Audit Chain Forking** | High volume concurrent writes cause race conditions where two entries use the same `prev_hash`. | FIFO async lock mutex (`acquireChainLock`) and PostgreSQL transaction advisory lock (`pg_advisory_xact_lock`) strictly serialize writes. | **MITIGATED** | `tests/security/audit-hardening.test.ts` |
| **T-29** | Log Injection | **Log Injection & CRLF Splitting** | Attacker embeds newline characters (`\r\n`) in filenames or notes to forge log entries. | `sanitizeLogString` and `sanitizeLogDetails` strip all newlines, carriage returns, null bytes, and ASCII control characters. | **MITIGATED** | `tests/security/audit-hardening.test.ts` |
| **T-30** | Access Control | **Self-Grant / Circular Privilege Inflation** | Document owner grants explicit grants to themselves or EDIT recipient attempts to share. | Self-grant rejected with 400 Validation Error; EDIT grants strictly restricted from invoking `share` or `delete` actions. | **MITIGATED** | `tests/security/auth-edge-cases.test.ts` |

---

## 2. Accepted Risks and Rationale

| Risk | Description | Why Accepted | Residual Risk & Compensating Control |
|:---|:---|:---|:---|
| **Database Superuser Tampering** | A PostgreSQL administrator with `SUPERUSER` or cloud DB root access can issue `ALTER TABLE audit_logs DISABLE TRIGGER ALL;` and rewrite rows. | In any database system, superusers have ultimate storage-level authority. | **Compensating Control**: HMAC-signed checkpoints exported to an external WORM (Write Once, Read Many) archive via `GET /api/admin/audit/checkpoint/export`. Any superuser alteration will fail verification against the external anchor. |
| **In-Flight Revocation on Active Streams** | If an owner revokes a grant mid-download of a large file, the active HTTP response stream has already begun. | Re-checking DB permissions for every 16 KB TCP packet would amplify database read queries by 1,000x and degrade streaming performance. | **Compensating Control**: 25 MB max file size ensures downloads complete in < 2 seconds. Subsequent range requests, previews, or re-downloads are rejected immediately. |
| **Absence of Multi-Factor Authentication (MFA)** | Authentication relies exclusively on email and Argon2id password hashing without TOTP/FIDO2. | Core system scope focused on authorization correctness and audit trail defense-in-depth rather than identity provider federation. | **Compensating Control**: Progressive account lockout (5 failed attempts = 15-minute lock), IP rate limiting, and instant session purge upon compromise. |
| **PGlite Embedded Concurrency** | In local zero-config mode, PGlite operates in-process within a single Node.js process. | Enables instant local development and clean-clone execution without Docker or external PostgreSQL services. | **Compensating Control**: Strict in-process FIFO async mutex guarantees sequential write serialization. Production deploys use standard PostgreSQL with `pg_advisory_xact_lock`. |

---

## 3. What I Would Do With More Time

1. **Per-Chunk Streaming Re-Validation**:
   For deployments handling 500 MB+ files, implement a custom readable stream transform that re-queries session status every 5 MB chunk, terminating TCP sockets mid-flight if revoked.
2. **External RFC 3161 Timestamping & Public Anchor**:
   Automate recurring background jobs that publish the latest checkpoint hash to an RFC 3161 cryptographic timestamping authority or public blockchain anchor (e.g. Bitcoin OP_RETURN or Ethereum smart contract) for independent third-party verification.
3. **Envelope Encryption at Rest with Per-Document Keys**:
   Encrypt every file on disk with an individual AES-256-GCM Data Encryption Key (DEK). Store DEKs wrapped by a hardware security module (AWS KMS / HashiCorp Vault), allowing cryptographic erasure simply by destroying the document's DEK.
4. **Asynchronous Malware & Polyglot Scanning**:
   Integrate a streaming ClamAV or sandbox scanner pipeline to detect steganographic payloads and macro malware inside verified DOCX/PDF containers.
5. **Hardware Security Keys (WebAuthn / FIDO2)**:
   Add WebAuthn passkey support for phishing-resistant hardware token authentication.
6. **Automated Cryptographic Retention Policies**:
   Implement mathematically verified redaction policies where expired documents can be safely shredded while preserving the unbroken integrity of the audit hash chain.
