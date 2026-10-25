# TrustVault — 5-Minute Evaluator Demo Script

> **Purpose**: A step-by-step walkthrough demonstrating the core promise of TrustVault:  
> *"The wrong person can never read a file, and we can prove who read it."*  
> **Estimated Execution Time**: ~5 minutes  
> **Pre-requisite**: App running on `http://localhost:3000` with clean deterministic seed (`npm run db:seed`).

---

## Pre-Seeded Identities & Credentials

| Role | Name | Email | Password | Primary Purpose |
|:---|:---|:---|:---|:---|
| **OWNER 1** | Alice Sterling | `alice.owner@meridian.test` | `OwnerPassword123!` | Document custodian, uploads files, grants & revokes ACLs |
| **OWNER 2** | Bob Vance | `bob.owner@apex.test` | `OwnerPassword456!` | Separate tenant, owns confidential engineering schematics |
| **VIEWER** | Carol Danvers | `carol.viewer@auditcorp.test` | `ViewerPassword123!` | External auditor, granted access to specific files only |
| **ADMIN** | System Custodian | `admin@trustvault.internal` | `AdminPassword123!` | Infrastructure custodian, manages users, verifies hash chain |

---

## Step 1: Default Deny & Tenant Isolation (0:00 - 1:00)

### Goal:
Prove that ungranted users have zero discovery or access rights, and receive uniform 404s without existence leakage.

### Instructions:
1. Open an incognito browser window and navigate to `http://localhost:3000/login`.
2. Sign in as **Carol Danvers** (Viewer):
   - Email: `carol.viewer@auditcorp.test`
   - Password: `ViewerPassword123!`
3. Notice that Carol lands on the Documents view.
   - Carol sees **only 1 document**: `Meridian Logistics Q3 Financial Audit` (the sole document explicitly granted to her).
   - Carol **does NOT see** Bob's confidential document (`Project Zephyr Hardware Schematics`) or Alice's ungranted contract (`Master Supply Agreement v2.1`).
4. In the URL bar, manually navigate to Bob's document ID:
   `http://localhost:3000/documents/<BOB_DOC_ID>` (or try any non-existent random UUID).
5. **Auditor Observation**:
   - The application renders an identical industrial `404 - OBJECT NOT LOCATED` screen.
   - Response status is `404 Not Found`.
   - Zero disclosure: titles, sizes, owners, or confirmation of existence are never leaked.

---

## Step 2: Granular Sharing & Grant Expiry (1:00 - 2:00)

### Goal:
Demonstrate granular ACL granting with strict TTL expiration.

### Instructions:
1. Open a second browser window and log in as **Alice Sterling** (Owner):
   - Email: `alice.owner@meridian.test`
   - Password: `OwnerPassword123!`
2. Click on **Master Supply Agreement v2.1**.
3. Click the **ACCESS CONTROL** tab.
   - Currently, no external users have access.
4. Click **GRANT ACCESS** button.
5. In the Issue Grant modal:
   - Target Email: `carol.viewer@auditcorp.test`
   - Access Level: `READ`
   - Expiration: Select `1 Day (24 Hours)` or `7 Days` preset.
6. Click **ISSUE CRYPTOGRAPHIC GRANT**.
7. **Auditor Observation**:
   - The access table updates immediately.
   - Carol is listed with `READ` permission and status `expires in 24h` (or `expires in 7d`).
   - The action is appended to the tamper-evident audit chain.

---

## Step 3: Instant Revocation (2:00 - 3:15)

### Goal:
Prove immediate revocation with zero cache lag or signed URL bypass.

### Instructions:
1. In Carol's browser window, refresh `http://localhost:3000/documents`.
2. Notice **Master Supply Agreement v2.1** now appears in Carol's list.
3. Click on the document and click **DOWNLOAD SECURE STREAM**.
   - The browser streams and downloads `master_supply_agreement.docx` successfully.
4. Switch back to Alice's window (Owner):
   - On the Access Control tab, click the red **REVOKE NOW** button next to Carol's name.
   - Confirm the revocation dialog.
5. Switch back to Carol's window:
   - Immediately click **DOWNLOAD SECURE STREAM** again (or refresh the page).
6. **Auditor Observation**:
   - Carol's download is **instantly refused** with an immediate `404 Not Found`.
   - There is zero waiting period, no signed URL window, and no cache TTL delay.
   - In Alice's **ACTIVITY** tab, an audit block is logged: `DENIED_ATTEMPT` with reason `NO_ACTIVE_GRANT_FOR_USER`.

---

## Step 4: Admin Boundary Isolation (3:15 - 4:15)

### Goal:
Demonstrate that System Administrators cannot snoop or download private documents without an explicit grant.

### Instructions:
1. Log in as **System Custodian** (Admin) in a third browser window:
   - Email: `admin@trustvault.internal`
   - Password: `AdminPassword123!`
2. Notice the navigation bar shows **ADMIN CONSOLE** (`/admin/audit`, `/admin/alerts`, `/admin/users`).
3. Attempt to fetch or download Alice's private financial document by opening:
   `http://localhost:3000/documents/<ALICE_DOC_ID>` or calling `/api/documents/<ALICE_DOC_ID>/download`.
4. **Auditor Observation**:
   - The request returns `404 Not Found`.
   - The Admin is strictly blocked by the central policy engine (`can(admin, 'download', doc) -> DENIED`).
   - The Admin possesses zero "God-mode" master key over document contents.
   - The denied attempt is synchronously logged in the global audit trail.

---

## Step 5: Cryptographic Chain Verification & Forensic Query (4:15 - 5:00)

### Goal:
Demonstrate real-time cryptographic audit chain verification and one-click forensic query.

### Instructions:
1. In the Admin console, navigate to **IMMUTABLE AUDIT EXPLORER** (`http://localhost:3000/admin/audit`).
2. Notice the green integrity badge: `● CHAIN VERIFIED (X BLOCKS)`.
3. Click the **VERIFY CHAIN** button:
   - The system re-hashes every sequential block: `hash_n = SHA256(prev_hash + canonical_json(row))`.
   - Compares the tip against signed checkpoints in `chain_checkpoints`.
   - Returns valid status with verified block count.
4. **Forensic Query**: "Who opened Alice's financial audit and when?"
   - In the **Document ID Filter** input, paste Alice's document ID.
   - Select Action: `DOWNLOADS ONLY` or `ALL ACTIONS`.
   - Click **QUERY**.
5. **Auditor Observation**:
   - The table renders the exact chronological access timeline for that document.
   - Displays exact timestamp (UTC), actor email (`carol.viewer@auditcorp.test`), IP address (`127.0.0.1`), action (`DOWNLOAD`), and outcome (`ALLOWED` / `DENIED`).
   - Click **EXPORT CSV STREAM** to download the signed forensic report for external auditors.

---

## Summary of Guarantees Demonstrated
- **Default Deny**: Ungranted files return uniform 404s with zero metadata leakage.
- **Immediate Revocation**: Taking access away takes effect instantly on the very next byte.
- **Admin Isolation**: Custodians cannot read private content without a grant.
- **Cryptographic Tamper-Evidence**: SHA-256 chain and HMAC external anchor guarantee audit log immutability.
