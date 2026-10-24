'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  FileText,
  Download,
  Share2,
  Trash2,
  Shield,
  Clock,
  History,
  Users,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  ArrowLeft,
  RefreshCw,
  Plus,
} from 'lucide-react';

interface DocumentDetail {
  id: string;
  title: string;
  originalFileName: string;
  mimeType: string;
  fileSize: number;
  category: string;
  folderPath: string;
  ownerId: string;
  ownerName: string;
  ownerEmail: string;
  currentVersion: number;
  sha256Checksum: string;
  createdAt: string;
  updatedAt: string;
}

interface GrantItem {
  id: string;
  userId: string;
  userEmail: string;
  userName: string;
  permission: 'READ' | 'EDIT';
  expiresAt: string | null;
}

interface ActivityItem {
  sequenceNumber: number;
  createdAt: string;
  action: string;
  outcome: 'ALLOWED' | 'DENIED';
  actorEmail: string;
  reason: string;
  rowHash: string;
}

interface VersionItem {
  id: string;
  versionNumber: number;
  originalFileName: string;
  fileSize: number;
  sha256Checksum: string;
  createdAt: string;
  creatorName: string;
}

interface AISuggestion {
  userId: string;
  email: string;
  fullName: string;
  suggestedPermission: 'READ' | 'EDIT';
  confidenceScore: number;
  reason: string;
}

export default function DocumentDetailPage({ params }: { params: { id: string } }) {
  const router = useRouter();
  const [activeTab, setActiveTab] = useState<'overview' | 'access' | 'activity' | 'versions'>('overview');
  const [document, setDocument] = useState<DocumentDetail | null>(null);
  const [effectivePermission, setEffectivePermission] = useState<string>('READ');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Tab Data States
  const [grants, setGrants] = useState<GrantItem[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [versions, setVersions] = useState<VersionItem[]>([]);

  // Share Dialog State
  const [shareOpen, setShareOpen] = useState(false);
  const [targetEmail, setTargetEmail] = useState('');
  const [permissionLevel, setPermissionLevel] = useState<'READ' | 'EDIT'>('READ');
  const [expiryDays, setExpiryDays] = useState('30');
  const [suggestions, setSuggestions] = useState<AISuggestion[]>([]);
  const [shareLoading, setShareLoading] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);

  // Version Upload State
  const [versionModalOpen, setVersionModalOpen] = useState(false);
  const [versionFile, setVersionFile] = useState<File | null>(null);
  const [versionUploading, setVersionUploading] = useState(false);

  async function loadDocument() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/documents/${params.id}`);
      if (!res.ok) {
        if (res.status === 404) {
          setError('Document not found or you do not have permission to view it.');
        } else {
          setError('Failed to load document details.');
        }
        return;
      }
      const data = await res.json();
      setDocument(data.document);
      setEffectivePermission(data.effectivePermission || 'READ');
    } catch {
      setError('An unexpected network error occurred.');
    } finally {
      setLoading(false);
    }
  }

  async function loadGrants() {
    try {
      const res = await fetch(`/api/documents/${params.id}/grants`);
      if (res.ok) {
        const data = await res.json();
        setGrants(data.grants || []);
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function loadActivity() {
    try {
      const res = await fetch(`/api/documents/${params.id}/activity`);
      if (res.ok) {
        const data = await res.json();
        setActivity(data.logs || []);
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function loadVersions() {
    try {
      const res = await fetch(`/api/documents/${params.id}/versions`);
      if (res.ok) {
        const data = await res.json();
        setVersions(data.versions || []);
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function loadSuggestions() {
    try {
      const res = await fetch(`/api/suggestions?documentId=${params.id}`);
      if (res.ok) {
        const data = await res.json();
        setSuggestions(data.suggestions || []);
      }
    } catch (e) {
      console.error(e);
    }
  }

  useEffect(() => {
    loadDocument();
  }, [params.id]);

  useEffect(() => {
    if (activeTab === 'access') {
      loadGrants();
      loadSuggestions();
    } else if (activeTab === 'activity') {
      loadActivity();
    } else if (activeTab === 'versions') {
      loadVersions();
    }
  }, [activeTab]);

  async function handleCreateGrant(e: React.FormEvent) {
    e.preventDefault();
    if (!targetEmail) return;

    setShareLoading(true);
    setShareError(null);

    try {
      let expiresAt: string | null = null;
      if (expiryDays !== 'never') {
        const days = parseInt(expiryDays, 10);
        expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
      }

      const res = await fetch(`/api/documents/${params.id}/grants`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          targetEmail,
          permission: permissionLevel,
          expiresAt,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || 'Failed to grant access');
      }

      // Log feedback if suggestion was accepted
      const matchingSuggestion = suggestions.find((s) => s.email.toLowerCase() === targetEmail.toLowerCase());
      if (matchingSuggestion) {
        await fetch('/api/suggestions/feedback', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            documentId: params.id,
            targetEmail,
            accepted: true,
          }),
        });
      }

      setTargetEmail('');
      setShareOpen(false);
      loadGrants();
    } catch (err: any) {
      setShareError(err.message);
    } finally {
      setShareLoading(false);
    }
  }

  async function handleRevoke(grantId: string, userEmail: string) {
    const confirmed = confirm(
      `Revoke access for ${userEmail}?\n\nCONSEQUENCE: ${userEmail} loses access immediately. Any active or subsequent download request will be terminated on the very next request.`
    );
    if (!confirmed) return;

    try {
      const res = await fetch(`/api/documents/${params.id}/grants/${grantId}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        loadGrants();
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function handleVersionUpload(e: React.FormEvent) {
    e.preventDefault();
    if (!versionFile) return;

    setVersionUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', versionFile);

      const res = await fetch(`/api/documents/${params.id}/versions`, {
        method: 'POST',
        body: formData,
      });

      if (res.ok) {
        setVersionModalOpen(false);
        setVersionFile(null);
        loadDocument();
        loadVersions();
      }
    } finally {
      setVersionUploading(false);
    }
  }

  if (loading) {
    return (
      <div className="py-20 text-center font-mono text-xs text-paper-dark">
        <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-accent" />
        <span>Validating central policy gate...</span>
      </div>
    );
  }

  if (error || !document) {
    return (
      <div className="max-w-md mx-auto py-20 text-center font-mono text-xs space-y-4">
        <div className="p-6 bg-ink-light border border-border-dark rounded-md">
          <span className="text-denied text-base font-bold block mb-2">■ HTTP 404 NOT FOUND</span>
          <p className="text-paper-dark/70 leading-relaxed mb-4">
            {error || 'Document not found or you do not possess valid access credentials.'}
          </p>
          <Link
            href="/documents"
            className="px-4 py-2 bg-accent text-white font-bold rounded inline-flex items-center gap-1.5"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Return to Vault
          </Link>
        </div>
      </div>
    );
  }

  const isOwner = effectivePermission === 'OWNER';

  return (
    <div className="space-y-6 font-mono text-xs">
      {/* Header Breadcrumb & Document Title */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border-dark">
        <div>
          <div className="flex items-center gap-2 text-paper-dark/60 text-[10px] uppercase mb-1">
            <Link href="/documents" className="hover:text-accent">VAULT</Link>
            <span>/</span>
            <span>{document.category}</span>
          </div>
          <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper">
            {document.title}
          </h1>
          <span className="text-[10px] text-paper-dark/40 block mt-0.5">
            {document.originalFileName} • v{document.currentVersion} • {(document.fileSize / 1024).toFixed(1)} KB
          </span>
        </div>

        <div className="flex items-center gap-3">
          {isOwner && (
            <button
              onClick={() => setShareOpen(true)}
              className="btn-industrial bg-paper text-ink hover:bg-paper-dark px-3 py-2 rounded flex items-center gap-1.5"
            >
              <Share2 className="w-3.5 h-3.5 text-accent" />
              <span>SHARE ACCESS</span>
            </button>
          )}

          <a
            href={`/api/documents/${document.id}/download`}
            className="btn-industrial bg-accent hover:bg-accent-hover text-white px-4 py-2 rounded flex items-center gap-1.5 font-bold"
          >
            <Download className="w-3.5 h-3.5" />
            <span>DOWNLOAD</span>
          </a>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex border-b border-border-dark font-mono text-xs">
        {[
          { key: 'overview', label: 'OVERVIEW', icon: FileText },
          { key: 'access', label: 'ACCESS CONTROL', icon: Users, show: isOwner },
          { key: 'activity', label: 'AUDIT TIMELINE', icon: Shield, show: isOwner },
          { key: 'versions', label: 'VERSIONS', icon: History },
        ]
          .filter((t) => t.show !== false)
          .map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as any)}
                className={`py-3 px-5 font-bold uppercase tracking-wider flex items-center gap-2 border-b-2 transition-colors ${
                  activeTab === tab.key
                    ? 'border-accent text-accent bg-ink-light/50'
                    : 'border-transparent text-paper-dark hover:text-paper'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
      </div>

      {/* Tab 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 bg-ink-light border border-border-dark rounded-md space-y-4">
            <span className="text-[10px] text-accent font-bold uppercase tracking-widest block">
              ■ CRYPTOGRAPHIC METADATA
            </span>

            <div>
              <span className="text-[10px] text-paper-dark/50 uppercase block">DOCUMENT SHA-256 CHECKSUM</span>
              <div className="text-[11px] font-bold text-paper break-all bg-ink p-2 rounded mt-1 border border-border-dark">
                {document.sha256Checksum}
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-[10px] text-paper-dark/50 uppercase block">CUSTODIAN OWNER</span>
                <span className="text-paper font-semibold block mt-0.5">{document.ownerName}</span>
                <span className="text-[10px] text-paper-dark/60 block">{document.ownerEmail}</span>
              </div>
              <div>
                <span className="text-[10px] text-paper-dark/50 uppercase block">CURRENT VERSION</span>
                <span className="text-paper font-bold block mt-0.5">Version {document.currentVersion}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-[10px] text-paper-dark/50 uppercase block">CLASSIFICATION</span>
                <span className="text-accent font-bold block mt-0.5">{document.category}</span>
              </div>
              <div>
                <span className="text-[10px] text-paper-dark/50 uppercase block">MIME TYPE</span>
                <span className="text-paper block mt-0.5">{document.mimeType}</span>
              </div>
            </div>
          </div>

          <div className="p-6 bg-ink-light border border-border-dark rounded-md space-y-4">
            <span className="text-[10px] text-allowed font-bold uppercase tracking-widest block">
              ■ POLICY EVALUATION CONTRACT
            </span>
            <div className="p-4 bg-ink border border-border-dark rounded space-y-2 text-[11px]">
              <div>
                <span className="text-paper-dark/50">Your Identity: </span>
                <span className="text-paper font-bold">{isOwner ? 'Document Owner' : 'Granted Reader'}</span>
              </div>
              <div>
                <span className="text-paper-dark/50">Effective Rights: </span>
                <span className="text-accent font-bold">{effectivePermission}</span>
              </div>
              <div>
                <span className="text-paper-dark/50">Revocation Guarantee: </span>
                <span className="text-allowed font-bold">Synchronous (Every Request)</span>
              </div>
            </div>

            <p className="text-[11px] text-paper-dark/60 leading-relaxed">
              Every download, preview, or byte slice streams through the central authorization gate.
              No pre-signed URLs exist that could bypass instant revocation.
            </p>
          </div>
        </div>
      )}

      {/* Tab 2: ACCESS CONTROL */}
      {activeTab === 'access' && (
        <div className="space-y-6">
          {/* AI Sharing Suggestions Banner */}
          {suggestions.length > 0 && (
            <div className="p-4 bg-ink-light border border-accent/40 rounded-md">
              <div className="flex items-center gap-2 text-accent font-bold mb-2">
                <Sparkles className="w-4 h-4" />
                <span className="uppercase text-[11px] tracking-wider">AI SHARING SUGGESTIONS (CONFIRM-ONLY)</span>
              </div>
              <p className="text-[10px] text-paper-dark/70 mb-3">
                Suggested based on category ({document.category}) and historical collaboration. The machine NEVER widens access on its own. Click a chip to pre-fill the grant dialog.
              </p>
              <div className="flex flex-wrap gap-2">
                {suggestions.map((sug) => (
                  <button
                    key={sug.email}
                    onClick={() => {
                      setTargetEmail(sug.email);
                      setPermissionLevel(sug.suggestedPermission);
                      setShareOpen(true);
                    }}
                    className="px-3 py-1.5 bg-ink border border-border-dark hover:border-accent text-paper rounded text-[11px] flex items-center gap-2 transition-colors"
                  >
                    <span className="font-bold text-accent">+ {sug.fullName}</span>
                    <span className="text-paper-dark/60 text-[10px]">({sug.suggestedPermission})</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Active Grants List */}
          <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden">
            <div className="p-4 bg-ink-dark border-b border-border-dark flex items-center justify-between">
              <span className="font-bold text-paper uppercase tracking-wider">ACTIVE ACCESS CONTROL LIST</span>
              <button
                onClick={() => setShareOpen(true)}
                className="px-3 py-1 bg-accent text-white font-bold rounded text-[11px]"
              >
                + GRANT USER
              </button>
            </div>

            {grants.length === 0 ? (
              <div className="py-12 text-center text-paper-dark/40">
                No external users currently hold access to this document. Only you (the owner) can view it.
              </div>
            ) : (
              <table className="w-full text-left">
                <thead className="bg-ink border-b border-border-dark text-[10px] text-paper-dark/50 uppercase tracking-widest">
                  <tr>
                    <th className="py-3 px-4">Named Individual</th>
                    <th className="py-3 px-4">Permission</th>
                    <th className="py-3 px-4">Expires</th>
                    <th className="py-3 px-4 text-right">Revocation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-dark/60">
                  {grants.map((g) => (
                    <tr key={g.id} className="hover:bg-ink/40 transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-bold text-paper block">{g.userName}</span>
                        <span className="text-[10px] text-paper-dark/50">{g.userEmail}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-ink border border-border-dark text-accent uppercase">
                          {g.permission}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-paper-dark">
                        {g.expiresAt ? new Date(g.expiresAt).toLocaleDateString() : 'NEVER'}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleRevoke(g.id, g.userEmail)}
                          className="px-2.5 py-1 bg-denied/15 border border-denied/40 text-denied hover:bg-denied/25 rounded text-[11px] font-bold"
                        >
                          REVOKE NOW
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: AUDIT TIMELINE */}
      {activeTab === 'activity' && (
        <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden">
          <div className="p-4 bg-ink-dark border-b border-border-dark font-bold text-paper uppercase tracking-wider">
            CRYPTOGRAPHIC ACCESS AUDIT TRAIL
          </div>

          {activity.length === 0 ? (
            <div className="py-12 text-center text-paper-dark/40">
              No audit logs recorded for this document yet.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="bg-ink border-b border-border-dark text-[10px] text-paper-dark/50 uppercase tracking-widest">
                  <tr>
                    <th className="py-3 px-4">#</th>
                    <th className="py-3 px-4">Timestamp (UTC)</th>
                    <th className="py-3 px-4">Action</th>
                    <th className="py-3 px-4">Outcome</th>
                    <th className="py-3 px-4">Actor</th>
                    <th className="py-3 px-4">Audit Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-dark/60">
                  {activity.map((act) => (
                    <tr
                      key={act.sequenceNumber}
                      className={act.outcome === 'DENIED' ? 'bg-denied/10' : 'hover:bg-ink/40'}
                    >
                      <td className="py-3 px-4 text-accent font-bold">#{act.sequenceNumber}</td>
                      <td className="py-3 px-4 text-paper-dark">{new Date(act.createdAt).toUTCString()}</td>
                      <td className="py-3 px-4 font-bold text-paper">{act.action}</td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            act.outcome === 'ALLOWED'
                              ? 'bg-allowed/20 text-allowed border border-allowed/40'
                              : 'bg-denied/20 text-denied border border-denied/40'
                          }`}
                        >
                          {act.outcome}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-paper">{act.actorEmail || 'Anonymous'}</td>
                      <td className="py-3 px-4 text-paper-dark/80">{act.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: VERSIONS */}
      {activeTab === 'versions' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center pb-2">
            <span className="font-bold uppercase tracking-wider text-paper">DOCUMENT REVISION HISTORY</span>
            {(isOwner || effectivePermission === 'EDIT') && (
              <button
                onClick={() => setVersionModalOpen(true)}
                className="px-3 py-1 bg-accent text-white font-bold rounded text-[11px] flex items-center gap-1.5"
              >
                <Plus className="w-3.5 h-3.5" /> UPLOAD NEW VERSION
              </button>
            )}
          </div>

          <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden">
            <table className="w-full text-left">
              <thead className="bg-ink-dark border-b border-border-dark text-[10px] text-paper-dark/50 uppercase tracking-widest">
                <tr>
                  <th className="py-3 px-4">Version</th>
                  <th className="py-3 px-4">File Name</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">SHA-256 Checksum</th>
                  <th className="py-3 px-4">Uploaded By</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60">
                {versions.map((v) => (
                  <tr key={v.id} className="hover:bg-ink/40">
                    <td className="py-3 px-4 font-bold text-accent">v{v.versionNumber}</td>
                    <td className="py-3 px-4 text-paper">{v.originalFileName}</td>
                    <td className="py-3 px-4 text-paper-dark">{(v.fileSize / 1024).toFixed(1)} KB</td>
                    <td className="py-3 px-4 text-paper-dark font-mono text-[10px] truncate max-w-xs">{v.sha256Checksum}</td>
                    <td className="py-3 px-4 text-paper-dark">{v.creatorName}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Share Grant Dialog */}
      {shareOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-ink border border-border-dark rounded-md max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border-dark">
              <span className="font-bold text-paper uppercase tracking-wider">■ ISSUE ACCESS CONTROL GRANT</span>
              <button onClick={() => setShareOpen(false)} className="text-paper-dark hover:text-paper">✕</button>
            </div>

            {shareError && (
              <div className="p-3 bg-denied/15 border border-denied/40 text-denied rounded text-[11px]">
                {shareError}
              </div>
            )}

            <form onSubmit={handleCreateGrant} className="space-y-4">
              <div>
                <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                  Recipient Corporate Email
                </label>
                <input
                  type="email"
                  required
                  value={targetEmail}
                  onChange={(e) => setTargetEmail(e.target.value)}
                  placeholder="colleague@domain.test"
                  className="w-full bg-ink-light border border-border-dark focus:border-accent p-2 rounded text-paper outline-none"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                  Access Level
                </label>
                <select
                  value={permissionLevel}
                  onChange={(e) => setPermissionLevel(e.target.value as any)}
                  className="w-full bg-ink-light border border-border-dark focus:border-accent p-2 rounded text-paper outline-none"
                >
                  <option value="READ">READ (View and Stream Download)</option>
                  <option value="EDIT">EDIT (View, Download, and Upload Revisions)</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                  Expiration Window
                </label>
                <select
                  value={expiryDays}
                  onChange={(e) => setExpiryDays(e.target.value)}
                  className="w-full bg-ink-light border border-border-dark focus:border-accent p-2 rounded text-paper outline-none"
                >
                  <option value="7">7 Days</option>
                  <option value="30">30 Days</option>
                  <option value="90">90 Days</option>
                  <option value="never">No Expiration (Indefinite)</option>
                </select>
              </div>

              <div className="p-3 bg-ink-light border border-border-dark rounded text-[10px] text-paper-dark/60">
                Revoking this grant in the future takes effect immediately on their next download or view request.
              </div>

              <div className="pt-2 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShareOpen(false)}
                  className="px-4 py-2 border border-border-dark rounded text-paper-dark hover:bg-ink-light"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={shareLoading}
                  className="btn-industrial bg-accent hover:bg-accent-hover text-white px-5 py-2 rounded font-bold disabled:opacity-50"
                >
                  {shareLoading ? 'GRANTING...' : '■ CONFIRM GRANT'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Version Upload Modal */}
      {versionModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-ink border border-border-dark rounded-md max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border-dark">
              <span className="font-bold text-paper uppercase tracking-wider">■ UPLOAD REVISION v{document.currentVersion + 1}</span>
              <button onClick={() => setVersionModalOpen(false)} className="text-paper-dark hover:text-paper">✕</button>
            </div>

            <form onSubmit={handleVersionUpload} className="space-y-4">
              <div>
                <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                  Select Revision File
                </label>
                <input
                  type="file"
                  required
                  onChange={(e) => setVersionFile(e.target.files?.[0] || null)}
                  className="w-full bg-ink-light border border-border-dark p-2 rounded text-paper file:mr-3 file:py-1 file:px-2 file:rounded file:border-0 file:text-[11px] file:font-mono file:bg-accent file:text-white"
                />
              </div>

              <div className="pt-2 flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setVersionModalOpen(false)}
                  className="px-4 py-2 border border-border-dark rounded text-paper-dark hover:bg-ink-light"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={versionUploading}
                  className="btn-industrial bg-accent hover:bg-accent-hover text-white px-5 py-2 rounded font-bold disabled:opacity-50"
                >
                  {versionUploading ? 'UPLOADING...' : '■ SAVE VERSION'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
