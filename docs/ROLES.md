# TrustVault — Roles and Security Boundaries

TrustVault adheres to the principle of least privilege. In contrast to legacy enterprise systems where an "Administrator" possesses a "God mode" master key to all sensitive corporate assets, TrustVault enforces strict cryptographic and authorization boundaries between system custodianship and confidential content access.

---

## The Default Rule: DENY

In TrustVault, authorization is strictly closed. If an explicit policy rule or active, unexpired grant does not permit an action, the evaluation immediately resolves to `DENY`. There are no implicit bypasses, universal superusers, or wildcard entitlements.

---

## Role Specifications

### 1. ADMIN (System Custodian & Auditor)

#### Capabilities:
- **User Management**: Invite users, adjust role assignments (`ADMIN`, `OWNER`, `VIEWER`), disable compromised user accounts (which instantly terminates active sessions).
- **Global Audit Trail Inspection**: View the immutable append-only audit trail across all system interactions, including authentication attempts, permission modifications, and security anomalies.
- **Integrity Verification**: Execute on-demand and scheduled cryptographic verification of the SHA-256 hash chain (`verifyChain()`), inspecting block hashes and sequence numbers.
- **Security Alerts & Telemetry**: Review automated detection alerts (brute force login bursts, bulk download spikes, after-hours access anomalies, and revoked-user access attempts).
- **Metadata Visibility**: View aggregate counts, categories, and system metadata.

#### Explicit Prohibition & Architectural Boundary:
> **An `ADMIN` CANNOT read, stream, download, or edit document contents unless explicitly granted access by the document owner, exactly like any ordinary user.**

#### Rationale: Why Admin Content Access is Blocked
1. **Separation of Custodianship from Data Ownership**: An infrastructure administrator's legitimate duty is to manage account lifecycles and verify system operational integrity. Reading confidential legal contracts, financial audits, executive communications, or trade secrets is NOT required to perform administrative maintenance.
2. **Mitigation of Compromised Administrative Credentials**: If an administrator's credentials are breached via phishing or malware, the attacker cannot exfiltrate the vault's contents. Exfiltration requires compromising the specific private document owners or convincing owners to grant access.
3. **Insider Threat Deterrence**: Malicious or coerced administrators cannot quietly browse private files without generating audit alarms or being blocked by the central policy engine.

---

### 2. OWNER (Document Custodian & Grantor)

#### Capabilities:
- **Document Management**: Upload new documents, organize documents with virtual folder paths and classification categories, upload subsequent document versions, rename, soft-delete, and restore own documents.
- **Granular Sharing Authority**: Grant and revoke `READ` or `EDIT` permissions to named individuals. May specify an optional expiration timestamp.
- **Activity Inspection**: View complete, chronological audit timelines of all access requests (including rejected unauthorized attempts) pertaining to documents they own.
- **Implicit Full Control**: An owner inherently possesses `view`, `download`, `edit`, `delete`, `share`, and `viewActivity` permissions on their owned documents unless the document is soft-deleted.

#### Restrictions:
- Cannot access or discover documents owned by other users unless explicitly granted.
- Cannot view the global system audit log or user directory management tools.

---

### 3. VIEWER (Granted Reader)

#### Capabilities:
- **Shared Document Access**: View metadata, inspect details, and stream/download contents of documents explicitly granted to them via an active, unexpired grant.
- **Shared Document Editing (Conditional)**: If granted `EDIT` permission, may update document metadata and upload newer versions.

#### Restrictions:
- **Zero Upload Rights**: Cannot upload new documents to the vault.
- **Zero Sharing Rights**: Cannot grant, delegate, or revoke access for any document.
- **Zero Deletion Rights**: Cannot delete, archive, or restore documents.
- **Zero Discovery Rights**: Cannot list, search, or probe documents they have not been granted. Any attempt to access an ungranted document returns an identical `404 Not Found` response.
