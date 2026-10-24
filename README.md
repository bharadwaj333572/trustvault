# ■ TRUSTVAULT — SECURE DOCUMENT SHARING & TAMPER-EVIDENT AUDIT TRAIL

> **"The wrong person can never read a file, and we can prove who read it."**

TrustVault is a security-first document management platform engineered for adversarial environments. It rejects signed URLs, long-lived JWTs, and client-side authorization assumptions. Every single file byte is streamed through a real-time policy evaluation chokepoint, and every action—allowed or denied—is permanently cryptographically chained in an append-only audit trail protected by PostgreSQL triggers.

---

## ■ STACK & RATIONALE

| Technology | Selection Rationale |
|:---|:---|
| **Next.js 14 (App Router)** | Full-stack unified runtime in TypeScript strict mode. Single deployable unit with zero distributed edge synchronization lag. |
| **PostgreSQL + PGlite** | Industrial SQL persistence with parameterised queries and BEFORE UPDATE/DELETE database triggers. Falls back seamlessly to embedded **PGlite** for self-contained, zero-external-dependency execution and instantaneous local cloning. |
| **Drizzle ORM** | Type-safe SQL dialect with zero query generation bloat. Guarantees authorization filtering is executed directly in SQL predicates rather than post-fetch in memory. |
| **Argon2id** | State-of-the-art password hashing (19 MiB memory cost, 2 iterations, 1 parallelism) to defeat GPU/ASIC password cracking. |
| **DB-Backed Opaque Sessions** | High-entropy random 128-bit tokens hashed SHA-256 in the database and delivered via `HttpOnly`, `SameSite=Lax`, `Secure` cookies. Allows **immediate session revocation** upon user suspension or logout. |
| **Private File Storage** | Private local volume (or S3-compatible bucket) completely unreachable by the public internet. Zero signed URLs. Filenames stored under random UUID keys; real names sanitized for display only. |
| **Vitest & Mutation Checks** | Comprehensive test suite (63+ automated tests) covering IDOR, mass assignment, race conditions, grant expiry, audit tampering, and a mutation testing suite. |
| **Tailwind CSS & Framer Motion** | High-precision industrial logistics design system (`--ink: #0B1220`, `--paper: #F0EFEA`, `--accent: #FF5A1F`). |

---

## ■ QUICK START (CLEAN CLONE)

TrustVault is engineered to clone and run in under 60 seconds with **zero external database setup required** (thanks to embedded PGlite).

### 1. Prerequisites
- **Node.js**: v18.17.0+ or v20+
- **npm** or **pnpm**

### 2. Clone and Install Dependencies
```bash
git clone https://github.com/your-org/trustvault.git
cd trustvault
npm install
```

### 3. Configure Environment
Copy the example environment configuration:
```bash
cp .env.example .env
```
*(The default `.env` is pre-configured to use embedded PGlite and local private storage `./storage` automatically. No edits required for local evaluation!)*

### 4. Seed the Database
Initialize schema, database triggers, seed users, documents, and the initial cryptographic audit blocks:
```bash
npx tsx scripts/seed.ts
```

### 5. Start the Development Server
```bash
npm run dev
```
Open **[http://localhost:3000](http://localhost:3000)** in your browser.

---

## ■ SEED CREDENTIALS

The deterministic seed script populates 4 isolated accounts representing each role and tenant:

| Role | Email Address | Password | Intended Test Vector |
|:---|:---|:---|:---|
| **ADMIN** | `admin@trustvault.internal` | `AdminPassword123!` | System audit exploration, alert dashboard, account lockouts. *Content isolation: Cannot view or download documents.* |
| **OWNER 1 (Alice)** | `alice.owner@meridian.test` | `OwnerPassword123!` | Document upload, version management, granting/revoking permissions, viewing document-specific activity. |
| **OWNER 2 (Bob)** | `bob.owner@apex.test` | `OwnerPassword456!` | Tenant isolation testing. Attempting to access Alice's documents returns 404. |
| **VIEWER (Carol)** | `carol.viewer@auditcorp.test` | `ViewerPassword123!` | Granted READ on Alice's audit document; denied all upload, edit, and deletion rights. |

---

## ■ RUNNING AUTOMATED TESTS

TrustVault is verified by 63 comprehensive unit, integration, and security tests.

### Run All Tests
```bash
npx vitest run
```

### Run Phase 9 Adversarial Attack Pass
```bash
npx vitest run tests/security/attack-pass.test.ts
```

### Run Policy Mutation Verification
To prove our tests are not toothless stubs, run the mutation test script which introduces deliberate policy bypasses and confirms the test suite fails:
```bash
npx tsx scripts/mutation-check.ts
```

---

## ■ AUDIT TRAIL VERIFICATION (TAMPER DETECTION)

TrustVault's audit trail forms a cryptographic SHA-256 hash chain:
$$\text{hash}_n = \text{SHA-256}(\text{prev\_hash}_{n-1} + \text{canonical\_json}(\text{row}_n))$$

### Verify via CLI
Run the standalone CLI audit verification script:
```bash
npx tsx scripts/verify-audit-chain.ts
```
Output:
```
=====================================================
  TrustVault Cryptographic Audit Chain Verification  
=====================================================

[1/2] Connecting to persistence engine...
[2/2] Fetching ordered audit blocks...

Verifying 7 sequential blocks...
  [Block 1] Sequence #1 -> HASH VERIFIED
  [Block 2] Sequence #2 -> HASH VERIFIED
  ...
✓ CHAIN INTEGRITY VERIFIED: All 7 blocks cryptographically sound.
  Genesis Anchor : 0000000000000000000000000000000000000000000000000000000000000000
  Chain Tip      : 1fc981b2ee31e93d...
```

### Verify via Admin UI
Log in as **Admin** (`admin@trustvault.internal`) and navigate to **System Audit** (`/admin/audit`). Click **"Re-Verify Chain"** to trigger a real-time recomputation of the entire hash chain.

---

## ■ CORE ARCHITECTURAL INVARIANTS

1. **Central Policy Engine (`can()`)**: All actions (`view`, `download`, `edit`, `delete`, `share`, `viewActivity`) pass through `src/server/policy/index.ts`. No scattered inline checks. Default is always `DENY`.
2. **Immediate Revocation**: No signed URLs. If a grant is revoked or a user is disabled, their very next file download request fails immediately.
3. **Admin Content Isolation**: The `ADMIN` role cannot read or download document contents unless explicitly granted like any other user. Admins manage users and inspect system audit metadata only.
4. **Uniform 404 Responses**: Unauthorized document requests return identical `404 Not Found` responses with uniform payload shapes to eliminate existence disclosure.
5. **Magic Byte Validation**: Files are sniffed at the binary level (first 512 bytes). Rejects executables (PE `MZ`, ELF) and active content (HTML, SVG).
6. **SQL-Level Authorization**: Search and document queries filter by ownership and active grants directly in SQL predicates.
7. **Safe AI Suggestions**: Deterministic co-occurrence suggestions only. Zero document contents are ever sent to an LLM. Grants require explicit human confirmation.

---

## ■ DEPLOYMENT GUIDE (CLEAN CLONE TO PRODUCTION)

TrustVault can be deployed to any host supporting Node.js and PostgreSQL (Docker, Render, Railway, Fly.io).

### Option A: Local Docker Compose
```bash
docker compose up --build
```
This launches a PostgreSQL container, mounts a private persistent volume for files, applies migrations, seeds demo accounts, and boots TrustVault on port 3000.

### Option B: Deploy to Render
1. Create a new **Web Service** on [Render.com](https://render.com) pointing to your repository.
2. Select **Node** environment.
3. Build command: `npm install && npm run build`
4. Start command: `npm start`
5. Create a **PostgreSQL** database on Render and set environment variable:
   - `DATABASE_URL`: `postgresql://...`
6. Add a persistent disk mounted to `/var/data/trustvault` and set:
   - `STORAGE_DIR`: `/var/data/trustvault`
7. Set secrets:
   - `SESSION_SECRET`: `$(openssl rand -hex 32)`
   - `COOKIE_SECURE`: `true`
   - `NODE_ENV`: `production`

### Option C: Deploy to Railway / Fly.io
1. Connect repo to Railway or Fly.io.
2. Attach a PostgreSQL addon.
3. Attach a persistent volume for private file storage.
4. Deploy using standard Next.js standalone output.

---

## ■ DOCUMENTATION SITEMAP

- [**docs/ROLES.md**](docs/ROLES.md) — Definitive role specifications (ADMIN, OWNER, VIEWER) and the Admin Content Isolation rationale.
- [**docs/PERMISSION_MODEL.md**](docs/PERMISSION_MODEL.md) — Pure document-level permission specification, what was deliberately NOT built (groups, inheritance), and why.
- [**docs/THREATS.md**](docs/THREATS.md) — 20-entry formal Threat Model and mitigation matrix.
- [**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md) — In-depth architectural design, schemas, hash chain math, and alert thresholds.
- [**docs/openapi.yaml**](docs/openapi.yaml) — OpenAPI 3.0 REST API specification.

---

## ■ KNOWN LIMITATIONS (TRANSPARENT DISCLOSURE)

In accordance with our engineering honesty principles, the following items are intentionally omitted or scoped as documented limitations:
1. **No MFA / TOTP**: Multi-factor authentication is not implemented in this version; auth relies on Argon2id passwords and DB session revocation.
2. **No Group Permissions**: By architectural design (see `docs/PERMISSION_MODEL.md`), grants are strictly per-user to eliminate complex inheritance loops and audit ambiguity.
3. **No Folder Inheritance**: Folders are virtual organization paths; permissions do not cascade down hierarchies.
4. **No Real-Time WebSockets**: Revocations are immediate on the very next HTTP request; open browser tabs do not close asynchronously via WebSocket pushes.
5. **PGlite In-Process Lock**: In local development with embedded PGlite, audit locking is handled in-process. In clustered production PostgreSQL deployments, `pg_advisory_xact_lock` should be configured for multi-node write serialization.
6. **No Email Delivery Provider**: Seed script generates dummy emails; password resets via SMTP are not included.

---

## ■ COMMIT HISTORY (PHASE PROGRESSION)

| Commit Hash | Phase | Description |
|:---|:---|:---|
| `d788f84` | Phase 1 | `feat(foundation)`: initialize TrustVault core schema, migrations, seed, design system, and PLAN.md |
| `55648af` | Phase 2 | `feat(auth)`: implement sessions, Argon2id, lockout, CSRF, and central policy engine with tests |
| `14b1e23` | Phase 3 | `feat(documents)`: implement magic-byte validation, private storage, SQL filtering, versions, and soft-delete |
| `5247b96` | Phase 4 | `feat(sharing)`: implement per-document grants, instant revocation, and automated revocation tests |
| `97a3c8e` | Phase 5 | `feat(audit)`: implement tamper-evident hash chain, append-only triggers, and verification suite |
| `0dd3dfe` | Phase 6 | `feat(admin)`: implement global audit explorer, CSV export, alerts engine, user management, and boundary isolation |
| `2c1040e` | Phase 7 | `feat(ai)`: implement AI sharing suggestions with confirm-only flow and non-widening tests |
| `ad6d8a9` | Phase 8 | `feat(ui)`: implement industrial logistics design system, landing page, dashboard, and custom 404 |
| `bf20e57` | Phase 9 | `security`: adversarial attack pass and mutation check |
