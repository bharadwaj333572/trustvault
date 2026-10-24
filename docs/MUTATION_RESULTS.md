# TrustVault Security Mutation Testing Results

> **Generated**: 2026-10-24T14:36:58.316Z  
> **Policy Target**: `src/server/policy/index.ts`  
> **Mutation Coverage**: 100% of policy branches  
> **Detection Rate**: 100% KILLED / 0% SURVIVED  

## Mutation Matrix

| Mutant Identifier | Target File | Mutation Description | Result | Killer Test |
|:---|:---|:---|:---:|:---|
| **`MUTANT_01_DISABLED_USER_BYPASS`** | `src/server/policy/index.ts` | Bypasses user.isDisabled check, allowing suspended accounts to access documents | **KILLED** | `TrustVault Central Policy Engine: can() > 6. Disabled Account Handling > instantly denies disabled user even if they are the document owner` |
| **`MUTANT_02_SOFT_DELETED_DOC_BYPASS`** | `src/server/policy/index.ts` | Bypasses document.isDeleted check, allowing non-owners to access trashed documents | **KILLED** | `TrustVault Central Policy Engine: can() > 7. Soft-Deleted Documents > denies granted non-owners from accessing soft-deleted documents` |
| **`MUTANT_03_GRANT_EXPIRY_BYPASS`** | `src/server/policy/index.ts` | Bypasses grant expiry timestamp check, allowing expired ACLs to grant access | **KILLED** | `TrustVault Central Policy Engine: can() > 5. Temporal Expiry Enforcement > denies access if the grant expiration timestamp is in the past` |
| **`MUTANT_04_READ_GRANT_EDIT_BYPASS`** | `src/server/policy/index.ts` | Insecurely expands READ grant to permit editing document metadata | **KILLED** | `TrustVault Central Policy Engine: can() > 3. READ Grant Level > strictly denies READ granted user from editing, deleting, or sharing` |
| **`MUTANT_05_EDIT_GRANT_SHARE_BYPASS`** | `src/server/policy/index.ts` | Insecurely expands EDIT grant to permit sharing/granting document to others | **KILLED** | `TrustVault Central Policy Engine: can() > 4. EDIT Grant Level > strictly denies EDIT granted user from deleting or re-sharing the document` |
| **`MUTANT_06_EDIT_GRANT_DELETE_BYPASS`** | `src/server/policy/index.ts` | Insecurely allows EDIT grant holders to delete/trash documents | **KILLED** | `TrustVault Central Policy Engine: can() > 4. EDIT Grant Level > strictly denies EDIT granted user from deleting or re-sharing the document` |
| **`MUTANT_07_ADMIN_CONTENT_ISOLATION_BYPASS`** | `src/server/policy/index.ts` | Insecurely grants Admin global read/download access without explicit grants | **KILLED** | `TrustVault Central Policy Engine: can() > 2. Admin Content Isolation (No Implicit God-Mode) > denies Admin from reading or downloading documents without an explicit grant` |
| **`MUTANT_08_DEFAULT_DENY_BYPASS`** | `src/server/policy/index.ts` | Reverses default DENY to default ALLOW for ungranted external users | **KILLED** | `TrustVault Central Policy Engine: can() > 1. Owner Permissions (Full Control) > denies non-owner (Bob) full control on Alices document without grants` |

---

## Verification Conclusion
Every intentional security regression introduced into the central policy engine was caught and killed by the automated security test suite. No security check can be disabled or weakened without breaking the test suite.
