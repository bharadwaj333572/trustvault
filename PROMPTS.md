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
  - PostgreSQL trigger compatibility across raw SQL migrations vs ORM schema generation.
  - Ensuring the database connection pool supports advisory locks (`pg_advisory_xact_lock`) without connection leakage across transactions.
  - Verification: Schema and triggers must strictly enforce append-only constraints both in development (PGlite / local Postgres) and in production environments.

---
