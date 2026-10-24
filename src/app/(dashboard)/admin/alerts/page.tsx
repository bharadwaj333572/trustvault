'use client';

import React, { useState, useEffect } from 'react';
import { AlertTriangle, ShieldAlert, RefreshCw, Clock, Flame } from 'lucide-react';

interface SecurityAlert {
  id: string;
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  title: string;
  description: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export default function AdminAlertsPage() {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [loading, setLoading] = useState(true);

  async function loadAlerts() {
    setLoading(true);
    try {
      const res = await fetch('/api/admin/alerts');
      if (res.ok) {
        const data = await res.json();
        setAlerts(data.alerts || []);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAlerts();
  }, []);

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border-dark">
        <div>
          <span className="eyebrow text-accent">■ ANOMALY DETECTION</span>
          <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
            AUTOMATED SECURITY ALERTS
          </h1>
        </div>

        <button
          onClick={loadAlerts}
          className="btn-industrial bg-ink-light border border-border-dark px-3 py-2 rounded text-paper hover:border-paper/40 flex items-center gap-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" /> RE-EVALUATE ALERTS
        </button>
      </div>

      {/* Threshold Definitions Box */}
      <div className="p-5 bg-ink-light border border-border-dark rounded-md space-y-2">
        <span className="text-[10px] text-accent font-bold uppercase tracking-widest block">
          ■ DOCUMENTED DEFINITIONS OF &quot;WORTH NOTICING&quot;
        </span>
        <ul className="text-[11px] text-paper-dark/70 space-y-1 list-disc pl-4 leading-relaxed">
          <li><strong>Cluster of Denied Attempts:</strong> $\ge 3$ rejected requests by the same IP or actor within 15 minutes.</li>
          <li><strong>Off-Hours Access:</strong> Logins or download streams executed between 00:00 and 05:00 UTC.</li>
          <li><strong>Bulk Exfiltration:</strong> $\ge 5$ document downloads executed by a single user within 10 minutes.</li>
          <li><strong>Revoked-User Probing:</strong> Attempts to read documents after a grant was revoked.</li>
          <li><strong>Account Lockouts:</strong> 5 consecutive password failures triggering backoff lockout.</li>
        </ul>
      </div>

      {/* Alerts Feed */}
      <div className="space-y-3">
        {loading ? (
          <div className="py-16 text-center text-paper-dark/50">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-accent" />
            <span>Evaluating telemetry heuristics...</span>
          </div>
        ) : alerts.length === 0 ? (
          <div className="py-16 text-center text-paper-dark/40 bg-ink-light border border-border-dark rounded-md">
            No active threat alerts detected in the current activity window.
          </div>
        ) : (
          alerts.map((al) => (
            <div
              key={al.id}
              className={`p-5 rounded-md border flex items-start justify-between gap-4 transition-colors ${
                al.severity === 'CRITICAL'
                  ? 'bg-denied/10 border-denied/50'
                  : al.severity === 'HIGH'
                  ? 'bg-accent/10 border-accent/40'
                  : 'bg-ink-light border-border-dark'
              }`}
            >
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                      al.severity === 'CRITICAL'
                        ? 'bg-denied text-white'
                        : al.severity === 'HIGH'
                        ? 'bg-accent text-white'
                        : 'bg-paper/20 text-paper'
                    }`}
                  >
                    {al.severity}
                  </span>
                  <span className="font-bold text-paper text-sm">{al.title}</span>
                </div>
                <p className="text-paper-dark/80 text-xs leading-relaxed">{al.description}</p>
                {al.metadata && (
                  <div className="text-[10px] text-paper-dark/50 font-mono mt-2 pt-2 border-t border-border-dark/40">
                    Metadata: {JSON.stringify(al.metadata)}
                  </div>
                )}
              </div>

              <span className="text-[10px] text-paper-dark/50 whitespace-nowrap">
                {new Date(al.timestamp).toISOString().replace('T', ' ').slice(0, 19)} UTC
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
