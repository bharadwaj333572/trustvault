# TrustVault — Permission Model Architecture

> "This is a security problem wearing the clothes of a CRUD app."

TrustVault prioritizes mathematical verifiability and instantaneous revocation over enterprise organizational complexity. This document explains the exact design choices made, what was intentionally omitted, and the calculated architectural costs.

---

## 1. What Was Chosen: Explicit Per-Document Named Grants

TrustVault adopts a **strict, direct per-document Access Control List (ACL)** model.

1. **Named User Targets**:
   Grants are issued exclusively to specific, identified system users via their unique User ID. There are no wildcard subjects (`*`), no role-based automatic document grants, and no anonymous link tokens.
2. **Discrete Permission Levels**:
   - `READ`: Allows viewing document metadata, viewing version history, and streaming the file contents.
   - `EDIT`: Allows `READ` capabilities plus uploading newer file versions and updating document title/category metadata.
3. **Temporal Boundedness (Expiry)**:
   Every grant can carry an optional ISO 8601 expiration timestamp. Once `expires_at <= NOW()`, the grant is rendered instantly inactive in constant time without requiring background batch cleanup jobs.
4. **Owner Primacy**:
   The user identified by `document.ownerId` retains intrinsic full control over the document (view, download, edit, delete, share, viewActivity).

---

## 2. The Central Policy Engine: Single Chokepoint

Authorization is strictly centralized in one pure function:
```typescript
can(user: SessionUser, action: PolicyAction, document: DocumentRecord, grants?: DocumentGrant[]): PolicyDecision
```

### Supported Actions:
- `view`: Inspect document metadata and overview.
- `download`: Stream file payload or range slices from private storage.
- `edit`: Alter document title, category, or submit a new version payload.
- `delete`: Soft-delete or restore a document.
- `share`: Create, modify, or revoke document grants.
- `viewActivity`: Retrieve audit trail events specific to the document.

### Non-Negotiable Rules of Policy Evaluation:
- **No Inline Checks**: No route handler, server component, or API controller ever executes `if (user.role === 'ADMIN')` or `if (doc.ownerId === user.id)`. Every authorization question delegates directly to `can()`.
- **SQL-Level Filtering**: Listing and search queries do not fetch candidates and filter in application memory. The database query itself joins `document_grants` with an active expiration clause and owner check (`WHERE owner_id = :uid OR (id IN (SELECT document_id FROM document_grants WHERE user_id = :uid AND (expires_at IS NULL OR expires_at > NOW()))))`.
- **Uniform Denial (No Existence Leaking)**: If a document does not exist, or if the requester fails policy evaluation, the application emits the exact same HTTP 404 status code and response body shape (`{ "error": { "code": "NOT_FOUND", "message": "Document or resource not found" } }`). The true authorization denial is captured exclusively in the tamper-evident internal audit log.

---

## 3. What Was Deliberately NOT Built (And Why)

In high-assurance security engineering, complexity is the primary source of vulnerabilities. TrustVault explicitly excludes three ubiquitous enterprise sharing features:

### A. User Groups and Department Hierarchies
- **What is excluded**: Group-level grants (e.g. `engineering-team`, `finance-contractors`), nested groups, and dynamic role memberships.
- **Why**: Group membership evaluation introduces stale cache windows, transitive permission leaks, and hidden access paths. When an auditor asks *"Who can read this file right now?"*, group models require traversing graph hierarchies and recursive directory lookups. In TrustVault, that answer is a single direct SQL query against `document_grants`.

### B. Hierarchical Folder Inheritance
- **What is excluded**: Cascading inherited permissions from parent directories to child directories and files (e.g., granting `/finance` automatically grants all nested documents).
- **Why**: Folder inheritance is the leading cause of accidental enterprise data exposure. A user moves a file into a folder or changes a folder's permission, inadvertently exposing hundreds of confidential files. In TrustVault, folders are purely virtual organizational tags (`folderPath: "/contracts/2026"`). Permissions belong strictly to the document entity.

### C. Public or "Anyone With The Link" Sharing
- **What is excluded**: Shareable random secret URLs, pre-signed S3 download URLs, and public guest view links.
- **Why**: A link that can be shared without authentication is a link that can be forwarded via email, leaked in Slack, or scraped from browser history. Furthermore, pre-signed URLs are impossible to revoke synchronously before their cryptographic expiration timestamp. TrustVault requires every single file download to originate from an active, authenticated session verified in real-time against the database.

---

## 4. What This Design Costs (Honest Architectural Trade-offs)

| Trade-off | The Cost | The Security Benefit Earned |
|---|---|---|
| **Administrative Overhead** | Owners must grant access to individuals one by one (or confirm batch suggestions individually). | Zero ambient permission sprawl. Every granted individual is explicitly known and audited. |
| **Server Bandwidth & CPU Load** | Every file download streams through the TrustVault server process rather than offloaded directly to CDN/S3 signed URLs. | Instantaneous revocation. When a grant is revoked, downloads terminate on the next millisecond, including active range requests. |
| **No "Drop-in" Massive Public Sharing** | Cannot be used as an anonymous file hosting service or public CDN. | Complete audit fidelity. Every byte downloaded is tied to a verified human identity in the cryptographic hash chain. |
