'use client';

import React, { useState, useEffect } from 'react';
import { Download, Search, Filter, Shield, RefreshCw } from 'lucide-react';

interface AuditLogItem {
  sequenceNumber: number;
  id: string;
  createdAt: string;
  action: string;
  outcome: 'ALLOWED' | 'DENIED';
  actorEmail: string;
  actorRole: string;
  ipAddress: string;
  documentId: string;
  reason: string;
  prevHash: string;
  rowHash: string;
}

export default function AdminAuditPage() {
  const [logs, setLogs] = useState<AuditLogItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionFilter, setActionFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [actorFilter, setActorFilter] = useState('');
  const [documentFilter, setDocumentFilter] = useState('');

  async function loadAudit() {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (actionFilter) params.set('action', actionFilter);
      if (outcomeFilter) params.set('outcome', outcomeFilter);
      if (actorFilter) params.set('actor', actorFilter);
      if (documentFilter) params.set('documentId', documentFilter);
      params.set('limit', '100');

      const res = await fetch(`/api/admin/audit?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setLogs(data.logs || []);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    // Check if documentId is present in URL query
    if (typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      const docParam = urlParams.get('documentId');
      if (docParam) {
        setDocumentFilter(docParam);
      }
    }
    loadAudit();
  }, [actionFilter, outcomeFilter]);

  function handleFilterSubmit(e: React.FormEvent) {
    e.preventDefault();
    loadAudit();
  }

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border-dark">
        <div>
          <span className="eyebrow text-accent">■ IMMUTABLE TIMELINE</span>
          <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
            GLOBAL AUDIT EXPLORER
          </h1>
        </div>

        <a
          href="/api/admin/audit?format=csv"
          className="btn-industrial bg-paper text-ink hover:bg-paper-dark px-4 py-2.5 rounded flex items-center gap-2 font-bold"
        >
          <Download className="w-4 h-4 text-accent" />
          <span>EXPORT CSV STREAM</span>
        </a>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 bg-ink-light border border-border-dark rounded-md flex flex-wrap items-center gap-4">
        <form onSubmit={handleFilterSubmit} className="flex-1 min-w-[180px]">
          <input
            type="text"
            value={actorFilter}
            onChange={(e) => setActorFilter(e.target.value)}
            placeholder="Filter by actor email..."
            className="w-full bg-ink border border-border-dark focus:border-accent px-3 py-1.5 rounded text-xs text-paper outline-none"
          />
        </form>

        <form onSubmit={handleFilterSubmit} className="flex-1 min-w-[220px]">
          <input
            type="text"
            value={documentFilter}
            onChange={(e) => setDocumentFilter(e.target.value)}
            placeholder="Document ID (Who opened doc X?)..."
            className="w-full bg-ink border border-border-dark focus:border-accent px-3 py-1.5 rounded text-xs text-paper outline-none font-mono"
          />
        </form>

        <select
          value={outcomeFilter}
          onChange={(e) => setOutcomeFilter(e.target.value)}
          className="bg-ink border border-border-dark px-3 py-1.5 rounded text-xs text-paper outline-none"
        >
          <option value="">ALL OUTCOMES</option>
          <option value="ALLOWED">ALLOWED ONLY</option>
          <option value="DENIED">DENIED ONLY (INTRUSIONS)</option>
        </select>

        <select
          value={actionFilter}
          onChange={(e) => setActionFilter(e.target.value)}
          className="bg-ink border border-border-dark px-3 py-1.5 rounded text-xs text-paper outline-none"
        >
          <option value="">ALL ACTIONS</option>
          <option value="DOWNLOAD">DOWNLOADS ONLY</option>
          <option value="VIEW">VIEWS ONLY</option>
          <option value="UPLOAD">UPLOADS</option>
          <option value="GRANT">GRANTS</option>
          <option value="REVOKE">REVOCATIONS</option>
          <option value="LOGIN_SUCCESS">LOGINS</option>
          <option value="DENIED_ATTEMPT">SECURITY INTRUSIONS</option>
        </select>

        <button
          type="button"
          onClick={loadAudit}
          className="bg-ink hover:bg-ink-dark border border-border-dark px-3 py-1.5 rounded text-paper font-bold flex items-center gap-1.5"
        >
          <Search className="w-3.5 h-3.5 text-accent" />
          <span>QUERY</span>
        </button>

        <button
          onClick={loadAudit}
          className="px-3 py-1.5 bg-accent text-white font-bold rounded flex items-center gap-1"
        >
          <RefreshCw className="w-3.5 h-3.5" /> REFRESH
        </button>
      </div>

      {/* Logs Table */}
      <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-paper-dark/50">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-accent" />
            <span>Scanning cryptographic audit blocks...</span>
          </div>
        ) : logs.length === 0 ? (
          <div className="py-16 text-center text-paper-dark/40">
            No audit records found matching criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-ink-dark border-b border-border-dark text-[10px] text-paper-dark/50 uppercase tracking-widest">
                <tr>
                  <th className="py-3 px-4">Seq #</th>
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Outcome</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4">Security Reason</th>
                  <th className="py-3 px-4">SHA-256 Hash</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60">
                {logs.map((log) => (
                  <tr
                    key={log.sequenceNumber}
                    className={log.outcome === 'DENIED' ? 'bg-denied/10' : 'hover:bg-ink/40'}
                  >
                    <td className="py-3 px-4 font-bold text-accent">#{log.sequenceNumber}</td>
                    <td className="py-3 px-4 text-paper-dark whitespace-nowrap">
                      {new Date(log.createdAt).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-3 px-4 font-bold text-paper whitespace-nowrap">{log.action}</td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          log.outcome === 'ALLOWED'
                            ? 'bg-allowed/20 text-allowed border border-allowed/40'
                            : 'bg-denied/20 text-denied border border-denied/40'
                        }`}
                      >
                        {log.outcome}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-paper truncate max-w-[150px]">{log.actorEmail || 'Anonymous'}</td>
                    <td className="py-3 px-4 text-paper-dark">{log.ipAddress || '-'}</td>
                    <td className="py-3 px-4 text-paper-dark/80 max-w-xs truncate">{log.reason || '-'}</td>
                    <td className="py-3 px-4 text-[10px] text-paper-dark/50 truncate max-w-[120px] font-mono">
                      {log.rowHash.slice(0, 16)}...
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
