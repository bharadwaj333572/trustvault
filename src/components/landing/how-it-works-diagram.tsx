'use client';

import React, { useState } from 'react';

const STEPS = [
  {
    step: '01',
    title: 'UPLOAD',
    desc: 'File magic bytes validated, encrypted storage key assigned, SHA-256 checksum stored.',
    callout: 'SHA-256',
  },
  {
    step: '02',
    title: 'GRANT',
    desc: 'Owner issues direct named grant to specific email (READ or EDIT) with optional expiry.',
    callout: 'GRANT: READ',
  },
  {
    step: '03',
    title: 'ACCESS CHECKED',
    desc: 'Every request, range slice, and preview is validated by central policy engine in real time.',
    callout: 'OWNER',
  },
  {
    step: '04',
    title: 'LOGGED IN CHAIN',
    desc: 'Every allowed or denied attempt is appended to the SHA-256 tamper-evident hash chain.',
    callout: 'CHAIN #1042',
  },
];

export function HowItWorksDiagram() {
  const [activeStep, setActiveStep] = useState<number | null>(null);

  return (
    <div className="w-full">
      {/* 4 Step Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        {STEPS.map((s, idx) => (
          <div
            key={s.step}
            onMouseEnter={() => setActiveStep(idx)}
            onMouseLeave={() => setActiveStep(null)}
            className={`p-4 border rounded transition-all cursor-pointer ${
              activeStep === idx
                ? 'bg-ink text-paper border-accent shadow-md scale-[1.02]'
                : 'bg-paper-light border-border-light text-ink hover:border-ink/40'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-xs font-bold text-accent">{s.step}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 bg-accent/10 text-accent rounded uppercase">
                {s.callout}
              </span>
            </div>
            <h4 className="font-display font-black text-sm uppercase tracking-tight">{s.title}</h4>
            <p className="text-xs text-ink/70 dark:text-paper/70 mt-1 leading-relaxed">{s.desc}</p>
          </div>
        ))}
      </div>

      {/* Annotated Document Visual with Leader Lines and Callouts */}
      <div className="relative bg-paper-light border border-border-light p-6 md:p-10 rounded-md overflow-hidden">
        <div className="max-w-md mx-auto bg-white border border-border-light rounded shadow-lg p-6 font-mono text-xs relative">
          {/* Header of mock document */}
          <div className="flex items-center justify-between border-b pb-3 mb-4">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 bg-accent rounded-sm" />
              <span className="font-bold text-ink">MERIDIAN_Q3_AUDIT.PDF</span>
            </div>
            <span className="text-[10px] text-ink/50 uppercase">2.4 MB</span>
          </div>

          {/* Callout 1: OWNER */}
          <div
            className={`p-2.5 rounded border mb-3 transition-colors ${
              activeStep === 2 ? 'bg-accent/15 border-accent' : 'bg-paper-light/50 border-border-light'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-ink/50 uppercase">■ CUSTODIAN</span>
              <span className="text-[10px] font-bold text-accent">OWNER: ALICE STERLING</span>
            </div>
            <div className="text-[11px] text-ink/80 mt-0.5">alice.owner@meridian.test (Implicit Full Control)</div>
          </div>

          {/* Callout 2: GRANT READ */}
          <div
            className={`p-2.5 rounded border mb-3 transition-colors ${
              activeStep === 1 ? 'bg-accent/15 border-accent' : 'bg-paper-light/50 border-border-light'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-ink/50 uppercase">■ ACTIVE ACL GRANT</span>
              <span className="text-[10px] font-bold text-allowed">LEVEL: READ</span>
            </div>
            <div className="text-[11px] text-ink/80 mt-0.5">Granted to carol.viewer@auditcorp.test (Exp: 2026-12-31)</div>
          </div>

          {/* Callout 3: SHA-256 Storage Integrity */}
          <div
            className={`p-2.5 rounded border mb-3 transition-colors ${
              activeStep === 0 ? 'bg-accent/15 border-accent' : 'bg-paper-light/50 border-border-light'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-ink/50 uppercase">■ CHECKSUM</span>
              <span className="text-[10px] font-bold text-ink">SHA-256</span>
            </div>
            <div className="text-[10px] text-ink/60 truncate mt-0.5">
              e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
            </div>
          </div>

          {/* Callout 4: Audit Chain Tip */}
          <div
            className={`p-2.5 rounded border transition-colors ${
              activeStep === 3 ? 'bg-accent/15 border-accent' : 'bg-paper-light/50 border-border-light'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-ink/50 uppercase">■ TAMPER-EVIDENT LOG</span>
              <span className="text-[10px] font-bold text-allowed">CHAIN #1042</span>
            </div>
            <div className="text-[10px] text-ink/60 mt-0.5">SHA-256(prev_hash + canonical_json) • Trigger protected</div>
          </div>
        </div>
      </div>
    </div>
  );
}
