'use client';

import React, { useState, useEffect } from 'react';
import { Smartphone, Laptop, ShieldCheck, AlertCircle, Trash2, CheckCircle2 } from 'lucide-react';

interface SessionItem {
  id: string;
  ipAddress: string;
  userAgent: string;
  createdAt: string;
  expiresAt: string;
  isCurrent: boolean;
}

export default function SessionsPage() {
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  async function loadSessions() {
    try {
      setLoading(true);
      const res = await fetch('/api/auth/sessions');
      if (!res.ok) throw new Error('Failed to load sessions');
      const data = await res.json();
      setSessions(data.sessions || []);
    } catch {
      setMessage({ type: 'error', text: 'Failed to load active sessions.' });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSessions();
  }, []);

  async function handleRevokeOthers() {
    if (!confirm('Are you sure you want to sign out of all other browsers and devices?')) return;
    setActionLoading(true);
    setMessage(null);
    try {
      const res = await fetch('/api/auth/sessions', { method: 'DELETE' });
      if (!res.ok) throw new Error('Failed to revoke sessions');
      setMessage({ type: 'success', text: 'All other devices have been signed out successfully.' });
      await loadSessions();
    } catch {
      setMessage({ type: 'error', text: 'Failed to revoke other sessions. Please try again.' });
    } finally {
      setActionLoading(false);
    }
  }

  function getDeviceIcon(ua: string) {
    if (ua.toLowerCase().includes('mobile') || ua.toLowerCase().includes('android') || ua.toLowerCase().includes('iphone')) {
      return <Smartphone className="w-5 h-5 text-accent" />;
    }
    return <Laptop className="w-5 h-5 text-paper-dark" />;
  }

  return (
    <div className="space-y-6">
      {/* Top Eyebrow and Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-border-dark pb-6">
        <div>
          <div className="flex items-center gap-2 font-mono text-[10px] text-accent tracking-widest uppercase">
            <span className="w-1.5 h-1.5 bg-accent" />
            <span>SESSION AUTHENTICATION & DEVICE HYGIENE</span>
          </div>
          <h1 className="text-2xl font-bold uppercase tracking-tight mt-1">ACTIVE SESSIONS</h1>
          <p className="text-xs text-paper-dark/70 mt-1">
            Manage your opaque DB-backed tokens across browsers and revoke access instantly.
          </p>
        </div>

        {sessions.length > 1 && (
          <button
            onClick={handleRevokeOthers}
            disabled={actionLoading}
            className="flex items-center gap-2 px-4 py-2 bg-denied/10 border border-denied text-denied text-xs font-mono font-bold uppercase hover:bg-denied hover:text-white transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            <span>{actionLoading ? 'REVOKING...' : 'SIGN OUT OTHER DEVICES'}</span>
          </button>
        )}
      </div>

      {message && (
        <div
          className={`p-3 text-xs font-mono flex items-center gap-2 border ${
            message.type === 'success'
              ? 'bg-allowed/10 border-allowed text-allowed'
              : 'bg-denied/10 border-denied text-denied'
          }`}
        >
          {message.type === 'success' ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
          <span>{message.text}</span>
        </div>
      )}

      {/* Session Cards Grid */}
      {loading ? (
        <div className="p-12 text-center text-xs font-mono text-paper-dark/50">
          <span className="inline-block w-2 h-2 bg-accent rounded-full animate-ping mr-2" />
          QUERYING SECURE SESSION STORE...
        </div>
      ) : sessions.length === 0 ? (
        <div className="p-12 text-center border border-dashed border-border-dark text-xs font-mono text-paper-dark/50">
          NO SESSIONS FOUND
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {sessions.map((s) => (
            <div
              key={s.id}
              className={`p-4 border transition-all ${
                s.isCurrent
                  ? 'border-accent bg-accent/5'
                  : 'border-border-dark bg-ink-dark/60 hover:border-paper-dark/30'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="p-2 border border-border-dark bg-ink">{getDeviceIcon(s.userAgent)}</div>
                  <div>
                    <div className="font-mono text-xs font-bold text-paper truncate max-w-[200px]">
                      {s.ipAddress}
                    </div>
                    <div className="text-[10px] text-paper-dark/60 font-mono truncate max-w-[220px]">
                      {s.userAgent}
                    </div>
                  </div>
                </div>

                {s.isCurrent ? (
                  <span className="px-2 py-0.5 bg-allowed/10 border border-allowed text-allowed text-[9px] font-mono font-bold tracking-wider">
                    CURRENT DEVICE
                  </span>
                ) : (
                  <span className="px-2 py-0.5 bg-paper/10 border border-border-dark text-paper-dark text-[9px] font-mono">
                    SECONDARY
                  </span>
                )}
              </div>

              <div className="mt-4 pt-3 border-t border-border-dark/60 flex items-center justify-between text-[10px] font-mono text-paper-dark/50">
                <span>AUTHENTICATED: {new Date(s.createdAt).toLocaleDateString()}</span>
                <span>EXPIRES: {new Date(s.expiresAt).toLocaleDateString()}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
