import React from 'react';
import Link from 'next/link';
import { TrustVaultLogo } from '@/components/ui/logo';
import { ShieldCheck, ArrowLeft, ExternalLink } from 'lucide-react';

const THREAT_MATRIX = [
  { id: 1, threat: 'IDOR on Document Downloads', exploit: 'Tampering document ID parameter in /api/documents/[id]/download to download ungranted file', mitigation: 'Central can(user, "download", doc) called on every request; returns uniform 404', test: 'idor_forbidden_download_fails_and_audits', status: 'MITIGATED' },
  { id: 2, threat: 'Forced Browsing / Unauthenticated Access', exploit: 'Invoking internal download routes without session cookie', mitigation: 'Middleware and session validation rejects unauthenticated requests with 401', test: 'unauthenticated_request_rejected', status: 'MITIGATED' },
  { id: 3, threat: 'Search & List Leakage', exploit: 'Calling search/list APIs to discover ungranted file titles or metadata', mitigation: 'SQL WHERE clause filters strictly by ownerId OR active grant before fetching', test: 'search_does_not_leak_unauthorized_records', status: 'MITIGATED' },
  { id: 4, threat: 'Role Escalation via Mass Assignment', exploit: 'Injecting role: "ADMIN" or role: "OWNER" into registration/profile update bodies', mitigation: 'Role fields in generic payloads are stripped and ignored; only Admin endpoint can modify roles', test: 'mass_assignment_role_escalation_ignored', status: 'MITIGATED' },
  { id: 5, threat: 'Mass Assignment on Uploads / Grants', exploit: 'Injecting ownerId or userId into upload or grant requests', mitigation: 'ownerId is strictly bound to session user ID; extra fields stripped by Zod', test: 'mass_assignment_owner_tampering_prevented', status: 'MITIGATED' },
  { id: 6, threat: 'Revoked-User Stale Token Exploitation', exploit: 'Using cached pre-signed URLs or download tokens after grant is revoked', mitigation: 'Zero signed URLs; files streamed through API with real-time DB grant query on every request', test: 'immediate_revocation_stops_subsequent_read', status: 'MITIGATED' },
  { id: 7, threat: 'Access to Soft-Deleted Documents', exploit: 'Requesting direct ID of a soft-deleted document', mitigation: 'Central policy engine denies soft-deleted documents to all non-owners (404)', test: 'soft_deleted_document_unreachable', status: 'MITIGATED' },
  { id: 8, threat: 'Magic-Byte MIME Spoofing', exploit: 'Renaming malicious executable (.exe/.elf) to .pdf or .png and uploading', mitigation: 'Binary magic-byte header inspection rejects non-whitelisted binaries regardless of extension', test: 'upload_magic_byte_validation_rejects_disguised_file', status: 'MITIGATED' },
  { id: 9, threat: 'Double Extension Attacks', exploit: 'Uploading files named document.pdf.exe or invoice.docx.php', mitigation: 'Sanitization strips dangerous extensions, random UUID storage keys decouple disk names', test: 'upload_double_extension_sanitized', status: 'MITIGATED' },
  { id: 10, threat: 'Stored XSS via File Downloads', exploit: 'Uploading malicious HTML/SVG containing script tags and opening in browser context', mitigation: 'Content-Disposition: attachment, X-Content-Type-Options: nosniff, strict CSP frame-ancestors none', test: 'download_headers_prevent_inline_xss', status: 'MITIGATED' },
  { id: 11, threat: 'Cross-Site Request Forgery (CSRF)', exploit: 'Malicious website submits hidden form to grant access or revoke documents', mitigation: 'Origin/Host header matching on all mutating HTTP methods + SameSite=Lax cookies', test: 'csrf_origin_mismatch_rejected', status: 'MITIGATED' },
  { id: 12, threat: 'Brute Force Credential Guessing', exploit: 'Automated script guesses passwords against login endpoint', mitigation: 'IP rate limit + exponential account lockout after 5 consecutive failed attempts', test: 'auth_lockout_after_consecutive_failures', status: 'MITIGATED' },
  { id: 13, threat: 'Audit Log SQL Tampering', exploit: 'Adversary with database write access attempts to UPDATE or DELETE audit records', mitigation: 'PostgreSQL BEFORE UPDATE and BEFORE DELETE triggers raise exceptions; DB role restricted', test: 'audit_table_update_trigger_raises_exception', status: 'MITIGATED' },
  { id: 14, threat: 'Audit Chain Concurrency Collision', exploit: 'Concurrent operations cause race condition resulting in branching hash chain', mitigation: 'Transaction advisory lock (pg_advisory_xact_lock) serializes audit insertions', test: 'audit_chain_concurrent_insert_preserves_order', status: 'MITIGATED' },
  { id: 15, threat: 'Silent Audit Failure on Sensitive Actions', exploit: 'Audit write fails, but sensitive download/grant proceeds without trace', mitigation: 'Audit failure throws unhandled exception that aborts the sensitive transaction', test: 'audit_failure_aborts_sensitive_operation', status: 'MITIGATED' },
  { id: 16, threat: 'Admin Overreach / Master Key Abuse', exploit: 'System Administrator downloads confidential private documents without grant', mitigation: 'can(adminUser, "download", doc) evaluates to false unless explicitly granted like any viewer', test: 'admin_cannot_download_unauthorized_document', status: 'MITIGATED' },
  { id: 17, threat: 'Timing and Existence Leakage', exploit: 'Attacker probes document IDs to determine if document exists (403 vs 404)', mitigation: 'Uniform 404 response payload and error code for both non-existent and ungranted documents', test: 'uniform_404_no_information_leak', status: 'MITIGATED' },
  { id: 18, threat: 'File Storage Path Traversal', exploit: 'Filename containing ../../../etc/passwd attempts to write or read outside sandbox', mitigation: 'Path traversal segments stripped via basename; disk keys are random v4 UUIDs', test: 'path_traversal_filename_normalized', status: 'MITIGATED' },
  { id: 19, threat: 'Race Condition Between Revoke and Range Read', exploit: 'Client requests partial range stream while owner executes revocation', mitigation: 'Policy and session re-evaluated on the start of every range request slice', test: 'revocation_race_condition_handled', status: 'MITIGATED' },
  { id: 20, threat: 'AI Suggestion Permission Widening', exploit: 'LLM suggestion engine grants permissions or leaks document contents', mitigation: 'Engine receives only metadata; suggestions grant zero access alone; confirm-only human UX', test: 'ai_suggestion_grants_zero_permissions_alone', status: 'MITIGATED' },
];

export default function SecurityPage() {
  return (
    <div className="min-h-screen bg-ink text-paper font-sans">
      <header className="border-b border-border-dark bg-ink/90 backdrop-blur sticky top-0 z-50">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <TrustVaultLogo />
          </Link>
          <Link
            href="/"
            className="flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-paper-dark hover:text-accent transition-colors"
          >
            <ArrowLeft className="w-4 h-4" /> Back to Home
          </Link>
        </div>
      </header>

      <main className="max-w-[1200px] mx-auto px-4 sm:px-6 py-12">
        <div className="mb-10 pb-6 border-b border-border-dark">
          <span className="eyebrow text-accent">■ ADVERSARIAL AUDIT DISCLOSURE</span>
          <h1 className="text-3xl sm:text-4xl font-display font-black uppercase tracking-tight text-paper mt-2">
            THREAT MATRIX & SECURITY ARCHITECTURE
          </h1>
          <p className="text-paper-dark/80 text-sm max-w-3xl mt-3 leading-relaxed">
            TrustVault is built with the assumption that an adversary with valid credentials will actively attempt to exfiltrate documents, bypass authorization checks, and tamper with audit logs. Every threat below is backed by an automated security test.
          </p>
        </div>

        <div className="overflow-x-auto border border-border-dark rounded-md bg-ink-light">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-ink-dark border-b border-border-dark text-[10px] text-paper-dark/60 uppercase tracking-widest">
              <tr>
                <th className="py-3 px-4">#</th>
                <th className="py-3 px-4">Threat Category</th>
                <th className="py-3 px-4">Exploit Vector</th>
                <th className="py-3 px-4">Mitigation Strategy</th>
                <th className="py-3 px-4">Automated Test Name</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-dark">
              {THREAT_MATRIX.map((t) => (
                <tr key={t.id} className="hover:bg-ink/50 transition-colors">
                  <td className="py-3 px-4 font-bold text-accent">{t.id.toString().padStart(2, '0')}</td>
                  <td className="py-3 px-4 font-bold text-paper whitespace-nowrap">{t.threat}</td>
                  <td className="py-3 px-4 text-paper-dark/80 text-[11px] leading-relaxed max-w-xs">{t.exploit}</td>
                  <td className="py-3 px-4 text-paper-dark text-[11px] leading-relaxed max-w-sm">{t.mitigation}</td>
                  <td className="py-3 px-4 text-accent text-[11px] whitespace-nowrap">{t.test}</td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-allowed/15 text-allowed font-bold text-[10px] tracking-wider uppercase">
                      {t.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
