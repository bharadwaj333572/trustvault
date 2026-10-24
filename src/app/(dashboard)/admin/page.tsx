'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  AlertTriangle,
  Lock,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Users,
  Activity,
  ArrowRight,
} from 'lucide-react';

interface VerificationStatus {
  badge: string;
  valid: boolean;
  totalEntries: number;
  lastVerifiedSequence: number;
  brokenAtSequence?: number;
  verifiedAt: string;
}

interface SecurityAlert {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  timestamp: string;
}

export default function AdminOverviewPage() {
  const [verifyStatus, setVerifyStatus] = useState<VerificationStatus | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);

  async function loadData() {
    setLoading(true);
    try {
      // 1. Load verification
      const verifyRes = await fetch('/api/admin/audit/verify');
      if (verifyRes.ok) {
        const vData = await verifyRes.json();
        setVerifyStatus(vData);
      }

      // 2. Load alerts
      const alertsRes = await fetch('/api/admin/alerts');
      if (alertsRes.ok) {
        const aData = await alertsRes.json();
        setAlerts(aData.alerts || []);
      }
    } finally {
      setLoading(false);
    }
  }

  async function runReverify() {
    setVerifying(true);
    try {
      const res = await fetch('/api/admin/audit/verify', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setVerifyStatus(data);
      }
    } finally {
      setVerifying(false);
    }
  }

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border-dark">
        <div>
          <span className="eyebrow text-accent">■ CUSTODIAN CONSOLE</span>
          <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
            INTEGRITY & AUDIT DASHBOARD
          </h1>
        </div>

        <button
          onClick={runReverify}
          disabled={verifying}
          className="btn-industrial bg-accent hover:bg-accent-hover text-white px-4 py-2.5 rounded flex items-center gap-2 font-bold disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
          <span>{verifying ? 'RECOMPUTING HASHES...' : '■ REVERIFY CHAIN'}</span>
        </button>
      </div>

      {/* Top Integrity Status Banner */}
      <div
        className={`p-6 border rounded-md flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
          verifyStatus?.valid
            ? 'bg-allowed/10 border-allowed/40 text-paper'
            : 'bg-denied/15 border-denied text-paper'
        }`}
      >
        <div className="flex items-center gap-4">
          {verifyStatus?.valid ? (
            <CheckCircle2 className="w-10 h-10 text-allowed flex-shrink-0" />
          ) : (
            <XCircle className="w-10 h-10 text-denied flex-shrink-0" />
          )}
          <div>
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded text-xs font-black tracking-wider uppercase ${
                  verifyStatus?.valid
                    ? 'bg-allowed/20 text-allowed border border-allowed/50'
                    : 'bg-denied text-white'
                }`}
              >
                ■ {verifyStatus?.badge || 'VERIFYING...'}
              </span>
              <span className="text-[10px] text-paper-dark/60">
                Checked: {verifyStatus?.verifiedAt ? new Date(verifyStatus.verifiedAt).toLocaleTimeString() : 'now'}
              </span>
            </div>
            <p className="text-xs text-paper-dark/80 mt-1.5">
              {verifyStatus?.valid
                ? `Cryptographic chain is 100% intact across all ${verifyStatus.totalEntries} ordered blocks up to sequence #${verifyStatus.lastVerifiedSequence}.`
                : `Tampering detected at block sequence #${verifyStatus?.brokenAtSequence}! Audit integrity has been compromised.`}
            </p>
          </div>
        </div>

        <div className="text-right">
          <span className="text-[10px] text-paper-dark/50 uppercase block">HASH ALGORITHM</span>
          <span className="text-xs font-bold text-accent">SHA-256 (Canonical JSON)</span>
        </div>
      </div>

      {/* Admin Notice on Content Isolation */}
      <div className="p-4 bg-ink-light border border-border-dark rounded-md text-[11px] text-paper-dark/70 leading-relaxed flex items-start gap-3">
        <Lock className="w-4 h-4 text-accent flex-shrink-0 mt-0.5" />
        <div>
          <span className="text-paper font-bold block mb-0.5">ARCHITECTURAL BOUNDARY REMINDER</span>
          As an Administrator, you possess authority over users, alerts, and audit trails. However, you CANNOT read or download document contents unless explicitly granted like any other user.
        </div>
      </div>

      {/* Grid of Alerts and Metrics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Security Alerts Panel */}
        <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden">
          <div className="p-4 bg-ink-dark border-b border-border-dark flex items-center justify-between">
            <div className="flex items-center gap-2 font-bold text-paper uppercase">
              <AlertTriangle className="w-4 h-4 text-accent" />
              <span>SECURITY ALERTS ({alerts.length})</span>
            </div>
            <Link href="/admin/alerts" className="text-accent hover:underline text-[11px]">
              View all →
            </Link>
          </div>

          <div className="divide-y divide-border-dark/60 max-h-96 overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="py-12 text-center text-paper-dark/40">
                No active security threshold violations detected.
              </div>
            ) : (
              alerts.map((al) => (
                <div key={al.id} className="p-4 hover:bg-ink/30 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                        al.severity === 'CRITICAL'
                          ? 'bg-denied/20 text-denied border border-denied/40'
                          : 'bg-accent/20 text-accent border border-accent/40'
                      }`}
                    >
                      {al.severity}
                    </span>
                    <span className="text-[10px] text-paper-dark/50">
                      {new Date(al.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <h4 className="font-bold text-paper text-xs">{al.title}</h4>
                  <p className="text-[11px] text-paper-dark/70 mt-1 leading-relaxed">{al.description}</p>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Quick Links & Telemetry */}
        <div className="space-y-4">
          <div className="p-5 bg-ink-light border border-border-dark rounded-md">
            <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block mb-1">
              AUDIT EXPLORER
            </span>
            <h3 className="font-display font-bold text-sm uppercase text-paper mb-2">
              GLOBAL CRYPTOGRAPHIC LOG
            </h3>
            <p className="text-paper-dark/70 text-[11px] mb-4">
              Filter through every authentication, upload, grant, revoke, and denied intrusion attempt. Export to CSV.
            </p>
            <Link
              href="/admin/audit"
              className="px-4 py-2 bg-paper text-ink font-bold rounded text-xs inline-flex items-center gap-1.5"
            >
              <span>OPEN AUDIT EXPLORER</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <div className="p-5 bg-ink-light border border-border-dark rounded-md">
            <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block mb-1">
              IDENTITY LIFECYCLE
            </span>
            <h3 className="font-display font-bold text-sm uppercase text-paper mb-2">
              USER ROLES & IMMEDIATE SESSIONS
            </h3>
            <p className="text-paper-dark/70 text-[11px] mb-4">
              Manage ADMIN, OWNER, and VIEWER roles. Disabling a user purges all active sessions immediately.
            </p>
            <Link
              href="/admin/users"
              className="px-4 py-2 bg-paper text-ink font-bold rounded text-xs inline-flex items-center gap-1.5"
            >
              <span>MANAGE USERS</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
