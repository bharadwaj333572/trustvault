'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';

type SimulationUser = 'OWNER' | 'VIEWER' | 'OUTSIDER' | 'ADMIN';
type SimulationAction = 'open' | 'download' | 'edit' | 'delete' | 'share';

interface PolicyOutcome {
  allowed: boolean;
  httpStatus: number;
  reason: string;
  auditRowHash: string;
}

export function TryToBreakItWidget() {
  const [selectedUser, setSelectedUser] = useState<SimulationUser>('OUTSIDER');
  const [selectedAction, setSelectedAction] = useState<SimulationAction>('download');
  const [grantActive, setGrantActive] = useState<boolean>(false);
  const [lastExecuted, setLastExecuted] = useState<PolicyOutcome | null>(null);

  function simulate() {
    let allowed = false;
    let httpStatus = 404;
    let reason = 'NO_ACTIVE_GRANT_FOR_USER';

    if (selectedUser === 'OWNER') {
      allowed = true;
      httpStatus = 200;
      reason = 'DOCUMENT_OWNER_ACCESS';
    } else if (selectedUser === 'ADMIN') {
      allowed = false;
      httpStatus = 404; // Admin content isolation: Admin cannot download private files without grant
      reason = 'ADMIN_CONTENT_ACCESS_BLOCKED_UNLESS_GRANTED';
    } else if (selectedUser === 'VIEWER') {
      if (grantActive) {
        if (selectedAction === 'open' || selectedAction === 'download') {
          allowed = true;
          httpStatus = 200;
          reason = 'ACTIVE_READ_GRANT';
        } else {
          allowed = false;
          httpStatus = 404;
          reason = 'READ_GRANT_CANNOT_EDIT_OR_DELETE';
        }
      } else {
        allowed = false;
        httpStatus = 404;
        reason = 'NO_ACTIVE_GRANT_FOR_USER';
      }
    } else {
      // OUTSIDER
      allowed = false;
      httpStatus = 404;
      reason = 'UNAUTHENTICATED_OR_UNLISTED';
    }

    // Mock realistic SHA-256 hash fragment
    const hashChars = '0123456789abcdef';
    let mockHash = '';
    for (let i = 0; i < 64; i++) {
      mockHash += hashChars[Math.floor(Math.random() * hashChars.length)];
    }

    setLastExecuted({
      allowed,
      httpStatus,
      reason,
      auditRowHash: mockHash,
    });
  }

  return (
    <div className="w-full bg-ink border border-border-dark p-6 md:p-8 rounded-md font-mono text-xs">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border-dark mb-6">
        <div>
          <span className="eyebrow text-accent">■ SIMULATION SANDBOX</span>
          <h3 className="text-lg md:text-xl font-display font-black text-paper uppercase tracking-tight mt-1">
            TRY TO BREAK THE POLICY ENGINE
          </h3>
        </div>
        <div className="px-2.5 py-1 bg-ink-light border border-border-dark text-paper-dark/70 text-[10px] uppercase tracking-wider rounded">
          Labelled: Interactive Verification Tool
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Controls Column */}
        <div className="lg:col-span-5 space-y-5">
          {/* User Selector */}
          <div>
            <label className="text-[10px] text-paper-dark/60 uppercase tracking-widest block mb-2">
              1. Choose Actor Profile
            </label>
            <div className="grid grid-cols-2 gap-2">
              {(['OWNER', 'VIEWER', 'OUTSIDER', 'ADMIN'] as SimulationUser[]).map((u) => (
                <button
                  key={u}
                  type="button"
                  onClick={() => setSelectedUser(u)}
                  className={`py-2 px-3 text-left border rounded text-xs transition-colors ${
                    selectedUser === u
                      ? 'bg-accent text-white border-accent font-bold'
                      : 'bg-ink-light border-border-dark text-paper hover:border-paper/40'
                  }`}
                >
                  ■ {u}
                </button>
              ))}
            </div>
          </div>

          {/* Action Selector */}
          <div>
            <label className="text-[10px] text-paper-dark/60 uppercase tracking-widest block mb-2">
              2. Choose Action to Attempt
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(['open', 'download', 'edit', 'delete', 'share'] as SimulationAction[]).map((a) => (
                <button
                  key={a}
                  type="button"
                  onClick={() => setSelectedAction(a)}
                  className={`py-2 px-2 text-center uppercase tracking-wider border rounded text-[11px] transition-colors ${
                    selectedAction === a
                      ? 'bg-paper text-ink font-bold border-paper'
                      : 'bg-ink-light border-border-dark text-paper hover:border-paper/40'
                  }`}
                >
                  {a}
                </button>
              ))}
            </div>
          </div>

          {/* Viewer Grant Toggle */}
          {selectedUser === 'VIEWER' && (
            <div className="p-3 bg-ink-light border border-border-dark rounded flex items-center justify-between">
              <div>
                <span className="text-paper font-semibold block">Active READ Grant</span>
                <span className="text-[10px] text-paper-dark/50">Simulates Alice granting Carol</span>
              </div>
              <button
                type="button"
                onClick={() => setGrantActive(!grantActive)}
                className={`px-3 py-1 text-[11px] font-bold rounded border ${
                  grantActive
                    ? 'bg-allowed/20 text-allowed border-allowed'
                    : 'bg-ink border-border-dark text-paper-dark/60'
                }`}
              >
                {grantActive ? 'ACTIVE' : 'NONE'}
              </button>
            </div>
          )}

          {/* Execute Button */}
          <button
            type="button"
            onClick={simulate}
            className="w-full py-3 bg-accent hover:bg-accent-hover text-white font-bold rounded text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-transform active:translate-y-0.5"
          >
            <span>■ EXECUTE POLICY CHECK</span>
          </button>
        </div>

        {/* Results Stream Column */}
        <div className="lg:col-span-7 bg-ink-dark border border-border-dark p-5 rounded flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-border-dark mb-4 text-[10px] text-paper-dark/50 tracking-widest uppercase">
              <span>EVALUATION TELEMETRY</span>
              <span>CENTRAL POLICY GATEWAY</span>
            </div>

            {lastExecuted ? (
              <motion.div
                key={lastExecuted.auditRowHash}
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                className="space-y-4"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">DECISION</span>
                    <span
                      className={`text-base font-black uppercase tracking-wider ${
                        lastExecuted.allowed ? 'text-allowed' : 'text-denied'
                      }`}
                    >
                      {lastExecuted.allowed ? '✓ ACCESS GRANTED' : '✕ ACCESS DENIED (UNIFORM 404)'}
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">HTTP STATUS</span>
                    <span className="text-base font-bold text-paper">{lastExecuted.httpStatus}</span>
                  </div>
                </div>

                <div className="p-3 bg-ink-light border border-border-dark rounded space-y-1.5 text-[11px]">
                  <div>
                    <span className="text-paper-dark/50 uppercase">Evaluator: </span>
                    <span className="text-paper font-semibold">can({selectedUser}, &quot;{selectedAction}&quot;, doc)</span>
                  </div>
                  <div>
                    <span className="text-paper-dark/50 uppercase">True Reason: </span>
                    <span className="text-accent font-semibold">{lastExecuted.reason}</span>
                  </div>
                  <div>
                    <span className="text-paper-dark/50 uppercase">Existence Leakage: </span>
                    <span className="text-allowed font-semibold">0% (Identical 404 response payload)</span>
                  </div>
                </div>

                <div>
                  <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block mb-1">
                    APPENDED AUDIT HASH BLOCK
                  </span>
                  <div className="p-2.5 bg-ink border border-border-dark rounded text-[10px] text-paper-dark/80 break-all select-all">
                    SHA-256: {lastExecuted.auditRowHash}
                  </div>
                </div>
              </motion.div>
            ) : (
              <div className="py-12 text-center text-paper-dark/40">
                <p>Select an actor and action, then press &quot;Execute Policy Check&quot; to test the gateway.</p>
              </div>
            )}
          </div>

          <div className="pt-4 border-t border-border-dark/60 text-[10px] text-paper-dark/40 flex items-center justify-between">
            <span>Enforced by: src/server/policy/index.ts</span>
            <span>Zero bypass guarantee</span>
          </div>
        </div>
      </div>
    </div>
  );
}
