'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface LogEvent {
  document: string;
  user: string;
  role: string;
  action: string;
  outcome: 'ALLOWED' | 'DENIED';
  reason: string;
  time: string;
  sequence: number;
}

const SAMPLE_EVENTS: LogEvent[] = [
  {
    document: 'meridian_q3_audit.pdf',
    user: 'carol.viewer@auditcorp.test',
    role: 'VIEWER',
    action: 'DOWNLOAD',
    outcome: 'ALLOWED',
    reason: 'ACTIVE_READ_GRANT',
    time: '14:22:04 UTC',
    sequence: 1042,
  },
  {
    document: 'project_zephyr_specs.pdf',
    user: 'carol.viewer@auditcorp.test',
    role: 'VIEWER',
    action: 'DOWNLOAD',
    outcome: 'DENIED',
    reason: 'NO_ACTIVE_GRANT_FOR_USER',
    time: '14:22:31 UTC',
    sequence: 1043,
  },
  {
    document: 'master_supply_agreement.docx',
    user: 'alice.owner@meridian.test',
    role: 'OWNER',
    action: 'REVOKE_GRANT',
    outcome: 'ALLOWED',
    reason: 'GRANT_REVOKED',
    time: '14:23:12 UTC',
    sequence: 1044,
  },
  {
    document: 'master_supply_agreement.docx',
    user: 'eve.outsider@unknown.net',
    role: 'UNAUTHENTICATED',
    action: 'READ_STREAM',
    outcome: 'DENIED',
    reason: 'UNAUTHENTICATED_ACCESS',
    time: '14:24:05 UTC',
    sequence: 1045,
  },
];

export function LiveAccessLogCard() {
  const [currentIndex, setCurrentIndex] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentIndex((prev) => (prev + 1) % SAMPLE_EVENTS.length);
    }, 3200);
    return () => clearInterval(timer);
  }, []);

  const event = SAMPLE_EVENTS[currentIndex];

  return (
    <div className="w-full max-w-md bg-ink-light border border-border-dark p-5 rounded font-mono text-xs shadow-2xl relative overflow-hidden">
      {/* Top Bar */}
      <div className="flex items-center justify-between pb-3 mb-4 border-b border-border-dark">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-allowed animate-pulse" />
          <span className="text-[11px] font-bold tracking-wider text-paper uppercase">
            LIVE ACCESS STREAM
          </span>
        </div>
        <span className="text-[10px] text-paper-dark/60 tracking-widest uppercase">
          CHAIN #{event.sequence}
        </span>
      </div>

      <AnimatePresence mode="wait">
        <motion.div
          key={event.sequence}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.2 }}
          className="space-y-3"
        >
          <div>
            <div className="text-[10px] text-paper-dark/50 tracking-widest uppercase">DOCUMENT</div>
            <div className="text-paper font-semibold text-sm truncate mt-0.5">{event.document}</div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-[10px] text-paper-dark/50 tracking-widest uppercase">ACTOR</div>
              <div className="text-paper truncate mt-0.5">{event.user}</div>
              <div className="text-[9px] text-accent mt-0.5">{event.role}</div>
            </div>
            <div>
              <div className="text-[10px] text-paper-dark/50 tracking-widest uppercase">ACTION</div>
              <div className="text-paper mt-0.5 font-bold">{event.action}</div>
              <div className="text-[10px] text-paper-dark/60">{event.time}</div>
            </div>
          </div>

          <div className="pt-2 border-t border-border-dark flex items-center justify-between">
            <div>
              <div className="text-[10px] text-paper-dark/50 tracking-widest uppercase">REASON</div>
              <div className="text-[11px] text-paper-dark mt-0.5">{event.reason}</div>
            </div>

            <div>
              <div className="text-[10px] text-paper-dark/50 tracking-widest uppercase mb-1">RESULT</div>
              <span
                className={`inline-block px-2.5 py-1 text-[11px] font-bold rounded-sm tracking-wider uppercase ${
                  event.outcome === 'ALLOWED'
                    ? 'bg-allowed/20 text-allowed border border-allowed/40'
                    : 'bg-denied/20 text-denied border border-denied/40'
                }`}
              >
                ■ {event.outcome}
              </span>
            </div>
          </div>
        </motion.div>
      </AnimatePresence>

      {/* Card Footer Caption */}
      <div className="mt-4 pt-3 border-t border-border-dark/60 flex items-center justify-between text-[10px] text-paper-dark/50">
        <span>Illustration of the audit trail</span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-1.5 h-1.5 bg-accent" /> SHA-256 VERIFIED
        </span>
      </div>
    </div>
  );
}
