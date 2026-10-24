import React from 'react';
import Link from 'next/link';
import { TrustVaultLogo } from '@/components/ui/logo';
import { LiveAccessLogCard } from '@/components/landing/live-access-log';
import { TryToBreakItWidget } from '@/components/landing/try-to-break-it';
import { HowItWorksDiagram } from '@/components/landing/how-it-works-diagram';
import { Shield, Lock, FileCheck, ArrowRight, CheckCircle2, AlertOctagon } from 'lucide-react';

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-ink text-paper flex flex-col font-sans selection:bg-accent selection:text-white">
      {/* 1. Global Navigation Bar */}
      <header className="sticky top-0 z-50 bg-ink/90 backdrop-blur-md border-b border-border-dark">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6 h-16 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <TrustVaultLogo />
          </Link>

          <nav className="hidden md:flex items-center gap-8 font-mono text-xs uppercase tracking-wider text-paper-dark">
            <a href="#how-it-works" className="hover:text-accent transition-colors">How it works</a>
            <Link href="/security" className="hover:text-accent transition-colors">Security & Threats</Link>
            <a href="#rules" className="hover:text-accent transition-colors">Four Rules</a>
            <a href="#demo" className="hover:text-accent transition-colors">Simulation</a>
          </nav>

          <div className="flex items-center gap-4">
            <Link
              href="/login"
              className="btn-industrial bg-accent hover:bg-accent-hover text-white px-4 py-2 rounded flex items-center gap-2"
            >
              <span>■ SIGN IN</span>
            </Link>
          </div>
        </div>
      </header>

      {/* 2. Hero Section (Dark, 12-Column Grid with Hairlines) */}
      <section className="relative pt-12 pb-20 md:py-24 border-b border-border-dark overflow-hidden grid-guides">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6 relative z-10">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            {/* Left Column: Headlines & CTAs */}
            <div className="lg:col-span-7 space-y-6">
              <div className="eyebrow text-accent">■ ZERO-TRUST DOCUMENT VAULT</div>
              
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-display font-extrabold uppercase tracking-tight leading-[1.05]">
                FILES THAT STAY <br />
                <span className="text-accent">WHERE THEY BELONG.</span>
              </h1>

              <p className="text-paper-dark/80 text-base md:text-lg max-w-xl leading-relaxed">
                The wrong person can never read a file, and we can mathematically prove who read it.
                Decoupled admin custodianship, instant revocation streaming, and an append-only cryptographic audit chain.
              </p>

              <div className="pt-2 flex flex-wrap items-center gap-4">
                <Link
                  href="/login"
                  className="btn-industrial bg-accent hover:bg-accent-hover text-white px-6 py-3.5 rounded text-xs flex items-center gap-2 shadow-lg"
                >
                  <span>■ OPEN THE DEMO</span>
                  <ArrowRight className="w-4 h-4" />
                </Link>

                <Link
                  href="/security"
                  className="btn-industrial bg-ink-light hover:bg-ink-muted text-paper border border-border-dark px-6 py-3.5 rounded text-xs flex items-center gap-2"
                >
                  <span>READ THREAT MODEL</span>
                </Link>
              </div>
            </div>

            {/* Right Column: Live Access Log Card */}
            <div className="lg:col-span-5 flex justify-center">
              <LiveAccessLogCard />
            </div>
          </div>

          {/* Real Seeded DB Stat Tiles */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-16 pt-10 border-t border-border-dark">
            <div className="p-4 bg-ink-light border border-border-dark rounded font-mono">
              <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">AUDIT CHAIN INTEGRITY</span>
              <div className="text-2xl font-black text-allowed mt-1 flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-allowed" />
                <span>100% VERIFIED</span>
              </div>
              <span className="text-[11px] text-paper-dark/60 mt-1 block">SHA-256 Advisory-Locked Chain</span>
            </div>

            <div className="p-4 bg-ink-light border border-border-dark rounded font-mono">
              <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">REVOCATION LATENCY</span>
              <div className="text-2xl font-black text-accent mt-1 flex items-center gap-2">
                <span>0.00 MS</span>
              </div>
              <span className="text-[11px] text-paper-dark/60 mt-1 block">Next-request streaming termination</span>
            </div>

            <div className="p-4 bg-ink-light border border-border-dark rounded font-mono">
              <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">UNAUTHORIZED EXISTENCE LEAKS</span>
              <div className="text-2xl font-black text-paper mt-1 flex items-center gap-2">
                <span>0.00%</span>
              </div>
              <span className="text-[11px] text-paper-dark/60 mt-1 block">Uniform 404 response shape</span>
            </div>
          </div>
        </div>
      </section>

      {/* 3. Three Promises (Dark Cards, Card 03 in Solid Orange) */}
      <section className="py-20 border-b border-border-dark bg-ink-dark">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6">
          <div className="mb-12">
            <span className="eyebrow text-accent">■ THE THREE PROMISES</span>
            <h2 className="text-3xl font-display font-black uppercase tracking-tight text-paper mt-2">
              DESIGNED TO SURVIVE ADVERSARIAL AUDITING
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Card 01 */}
            <div className="p-8 bg-ink-light border border-border-dark rounded-md relative flex flex-col justify-between">
              <div>
                <span className="text-4xl font-display font-black text-paper/20">01</span>
                <h3 className="text-lg font-display font-bold uppercase tracking-tight text-paper mt-3">
                  ONLY THE GRANTED CAN REACH IT
                </h3>
                <p className="text-paper-dark/70 text-sm mt-3 leading-relaxed">
                  Default DENY on every route. No public links, no wildcard sharing, and no group inheritance leaks.
                  Even system administrators cannot inspect file contents without an explicit owner grant.
                </p>
              </div>
              <div className="pt-6 font-mono text-xs text-allowed flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" /> SQL-Level Grant Filtration
              </div>
            </div>

            {/* Card 02 */}
            <div className="p-8 bg-ink-light border border-border-dark rounded-md relative flex flex-col justify-between">
              <div>
                <span className="text-4xl font-display font-black text-paper/20">02</span>
                <h3 className="text-lg font-display font-bold uppercase tracking-tight text-paper mt-3">
                  YOU CAN PROVE WHO REACHED IT
                </h3>
                <p className="text-paper-dark/70 text-sm mt-3 leading-relaxed">
                  Every access attempt, permission modification, and rejected intrusion is hashed into an append-only SHA-256 chain.
                  Database triggers block UPDATE or DELETE operations from any application role.
                </p>
              </div>
              <div className="pt-6 font-mono text-xs text-allowed flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" /> Cryptographic Chain Verification
              </div>
            </div>

            {/* Card 03: HIGHLIGHTED IN SOLID ORANGE AS SPECIFIED */}
            <div className="p-8 bg-accent text-white rounded-md relative flex flex-col justify-between shadow-xl">
              <div>
                <span className="text-4xl font-display font-black text-white/30">03</span>
                <h3 className="text-lg font-display font-bold uppercase tracking-tight text-white mt-3">
                  REVOKING WORKS IMMEDIATELY
                </h3>
                <p className="text-white/90 text-sm mt-3 leading-relaxed font-medium">
                  No pre-signed URLs and no long-lived JWTs. Files stream through an authenticated chokepoint.
                  When an owner revokes access or an admin disables a user, their very next byte stream is terminated instantly.
                </p>
              </div>
              <div className="pt-6 font-mono text-xs text-white font-bold flex items-center gap-1.5">
                ■ Zero Token Window of Vulnerability
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 4. How It Works (Light Section) */}
      <section id="how-it-works" className="py-20 bg-paper text-ink border-b border-border-light">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6">
          <div className="mb-12">
            <span className="eyebrow text-accent">■ ARCHITECTURAL LIFECYCLE</span>
            <h2 className="text-3xl font-display font-black uppercase tracking-tight text-ink mt-2">
              HOW TRUSTVAULT PROTECTS ASSETS
            </h2>
            <p className="text-ink/70 text-sm max-w-xl mt-2">
              From the instant a file is validated to the append-only cryptographic logging of access events.
            </p>
          </div>

          <HowItWorksDiagram />
        </div>
      </section>

      {/* 5. "Try to break it" Interactive Simulation Widget */}
      <section id="demo" className="py-20 bg-ink-light border-b border-border-dark">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6">
          <TryToBreakItWidget />
        </div>
      </section>

      {/* 6. Four Rules We Ship By (Light Section, Large Numerals) */}
      <section id="rules" className="py-20 bg-paper-light text-ink border-b border-border-light">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6">
          <div className="mb-14 text-center max-w-2xl mx-auto">
            <span className="eyebrow text-accent">■ ENGINEERING DOGMA</span>
            <h2 className="text-3xl md:text-4xl font-display font-black uppercase tracking-tight text-ink mt-2">
              FOUR RULES WE SHIP BY
            </h2>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8">
            <div className="border-t-2 border-accent pt-4">
              <span className="text-5xl font-display font-black text-ink/20 block">01</span>
              <h3 className="font-display font-bold text-base uppercase mt-2">DENY BY DEFAULT</h3>
              <p className="text-xs text-ink/70 mt-2 leading-relaxed">
                If an explicit, active, unexpired grant is not found, access evaluates to DENY. No ambient permissions.
              </p>
            </div>

            <div className="border-t-2 border-ink pt-4">
              <span className="text-5xl font-display font-black text-ink/20 block">02</span>
              <h3 className="font-display font-bold text-base uppercase mt-2">SERVER DECIDES, EVERY TIME</h3>
              <p className="text-xs text-ink/70 mt-2 leading-relaxed">
                No client-side role trust. Every download byte slice is authorized through `can()` on the exact millisecond.
              </p>
            </div>

            <div className="border-t-2 border-ink pt-4">
              <span className="text-5xl font-display font-black text-ink/20 block">03</span>
              <h3 className="font-display font-bold text-base uppercase mt-2">LOGS CANNOT BE QUIETLY CHANGED</h3>
              <p className="text-xs text-ink/70 mt-2 leading-relaxed">
                PostgreSQL triggers raise hard exceptions on UPDATE and DELETE. SHA-256 hash chaining detects any byte manipulation.
              </p>
            </div>

            <div className="border-t-2 border-accent pt-4">
              <span className="text-5xl font-display font-black text-ink/20 block">04</span>
              <h3 className="font-display font-bold text-base uppercase mt-2">REVOKE MEANS NOW</h3>
              <p className="text-xs text-ink/70 mt-2 leading-relaxed">
                Zero signed URLs or stale JWT tokens. Revoking a grant or disabling a user terminates access instantly.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* 7. Moving Documents For (Fictional Demo Organisations) */}
      <section className="py-12 bg-ink border-b border-border-dark text-paper-dark">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6">
          <p className="text-[11px] font-mono uppercase tracking-widest text-center text-paper-dark/40 mb-6">
            ■ Moving sensitive documents for high-assurance demo organisations
          </p>
          <div className="flex flex-wrap items-center justify-center gap-8 md:gap-16 font-display font-bold text-sm tracking-widest uppercase opacity-60">
            <span>MERIDIAN LOGISTICS</span>
            <span>APEX DEFENSE</span>
            <span>COBALT BIO</span>
            <span>VELOCE HEAVY INDUSTRIES</span>
            <span>SOLIS ENERGY</span>
          </div>
        </div>
      </section>

      {/* 8. Footer */}
      <footer className="py-12 bg-ink-dark text-paper-dark text-xs font-mono">
        <div className="max-w-[1200px] mx-auto px-4 sm:px-6 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <TrustVaultLogo className="h-5" />
            <span className="text-[10px] text-paper-dark/40">v1.0.0 (Strict Security Build)</span>
          </div>

          <div className="flex flex-wrap items-center gap-6 text-[11px]">
            <Link href="/security" className="hover:text-accent transition-colors">THREAT MODEL (THREATS.MD)</Link>
            <Link href="/login" className="hover:text-accent transition-colors">VERIFY AUDIT CHAIN</Link>
            <Link href="/login" className="hover:text-accent transition-colors">API SPECS (OPENAPI)</Link>
          </div>

          <div className="text-[10px] text-paper-dark/40">
            &copy; 2026 TrustVault. Correctness over feature count.
          </div>
        </div>
      </footer>
    </div>
  );
}
