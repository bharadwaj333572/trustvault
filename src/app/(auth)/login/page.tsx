'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { TrustVaultLogo } from '@/components/ui/logo';
import Link from 'next/link';
import { Lock, Mail, ArrowRight, AlertCircle, KeyRound, ShieldAlert } from 'lucide-react';

const QUICK_CREDS = [
  { label: 'Admin (Custodian)', email: 'admin@trustvault.internal', role: 'ADMIN', pass: 'AdminPassword123!' },
  { label: 'Owner 1 (Alice)', email: 'alice.owner@meridian.test', role: 'OWNER', pass: 'OwnerPassword123!' },
  { label: 'Owner 2 (Bob)', email: 'bob.owner@apex.test', role: 'OWNER', pass: 'OwnerPassword456!' },
  { label: 'Viewer (Carol)', email: 'carol.viewer@auditcorp.test', role: 'VIEWER', pass: 'ViewerPassword123!' },
];

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error?.message || 'Authentication failed');
      }

      if (data.user?.role === 'ADMIN') {
        router.push('/admin');
      } else {
        router.push('/documents');
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function fillCreds(cred: (typeof QUICK_CREDS)[0]) {
    setEmail(cred.email);
    setPassword(cred.pass);
    setError(null);
  }

  return (
    <div className="min-h-screen bg-ink text-paper flex flex-col justify-center items-center p-4 font-sans selection:bg-accent selection:text-white">
      <div className="w-full max-w-md">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex justify-center mb-4">
            <TrustVaultLogo />
          </Link>
          <div className="eyebrow text-accent">■ ACCESS CONTROL GATEWAY</div>
          <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
            AUTHENTICATE SESSION
          </h1>
        </div>

        {/* 1-Click Seed Credentials Selector */}
        <div className="bg-ink-light border border-border-dark p-4 rounded-md mb-6 font-mono text-xs">
          <div className="flex items-center gap-1.5 text-accent font-bold uppercase text-[10px] tracking-wider mb-2.5">
            <KeyRound className="w-3.5 h-3.5" /> Quick Fill Demo Personas
          </div>
          <div className="grid grid-cols-2 gap-2">
            {QUICK_CREDS.map((cred) => (
              <button
                key={cred.email}
                type="button"
                onClick={() => fillCreds(cred)}
                className="py-1.5 px-2 bg-ink border border-border-dark hover:border-accent text-left rounded text-[11px] transition-colors truncate"
              >
                <div className="font-bold text-paper truncate">{cred.label}</div>
                <div className="text-[9px] text-paper-dark/60">{cred.role}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Login Card */}
        <div className="bg-ink-light border border-border-dark p-6 sm:p-8 rounded-md shadow-2xl">
          {error && (
            <div className="mb-5 p-3 bg-denied/15 border border-denied/40 rounded flex items-start gap-2.5 text-xs text-paper font-mono">
              <ShieldAlert className="w-4 h-4 text-denied flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-widest text-paper-dark/70 mb-1.5">
                Corporate Email Address
              </label>
              <div className="relative">
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@company.test"
                  className="w-full bg-ink border border-border-dark focus:border-accent px-3 py-2.5 pl-9 rounded text-sm text-paper placeholder-paper-dark/30 font-mono outline-none transition-colors"
                />
                <Mail className="w-4 h-4 text-paper-dark/40 absolute left-3 top-3" />
              </div>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-widest text-paper-dark/70 mb-1.5">
                Password (Argon2id Hashed)
              </label>
              <div className="relative">
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full bg-ink border border-border-dark focus:border-accent px-3 py-2.5 pl-9 rounded text-sm text-paper placeholder-paper-dark/30 font-mono outline-none transition-colors"
                />
                <Lock className="w-4 h-4 text-paper-dark/40 absolute left-3 top-3" />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 py-3 bg-accent hover:bg-accent-hover disabled:opacity-50 text-white font-mono font-bold text-xs uppercase tracking-wider rounded flex items-center justify-center gap-2 transition-transform active:translate-y-0.5"
            >
              {loading ? (
                <span>■ VERIFYING CREDENTIALS...</span>
              ) : (
                <>
                  <span>■ SIGN IN TO VAULT</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="mt-6 pt-4 border-t border-border-dark text-center font-mono text-[10px] text-paper-dark/40">
            Session is stored in an HttpOnly, SameSite=Lax cookie.
          </div>
        </div>

        <div className="mt-6 text-center">
          <Link href="/" className="font-mono text-xs text-paper-dark/60 hover:text-accent transition-colors">
            ← Return to Public Overview
          </Link>
        </div>
      </div>
    </div>
  );
}
