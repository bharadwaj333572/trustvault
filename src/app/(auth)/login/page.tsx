'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { TrustVaultLogo } from '@/components/ui/logo';
import Link from 'next/link';
import { Lock, Mail, ArrowRight, KeyRound, ShieldAlert, User, UserPlus, CheckCircle2 } from 'lucide-react';

const QUICK_CREDS = [
  { label: 'Admin (Custodian)', email: 'admin@trustvault.internal', role: 'ADMIN', pass: 'AdminPassword123!' },
  { label: 'Owner 1 (Alice)', email: 'alice.owner@meridian.test', role: 'OWNER', pass: 'OwnerPassword123!' },
  { label: 'Owner 2 (Bob)', email: 'bob.owner@apex.test', role: 'OWNER', pass: 'OwnerPassword456!' },
  { label: 'Viewer (Carol)', email: 'carol.viewer@auditcorp.test', role: 'VIEWER', pass: 'ViewerPassword123!' },
];

function AuthForm() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (searchParams.get('mode') === 'register' || searchParams.get('tab') === 'register') {
      setMode('register');
    }
  }, [searchParams]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === 'register') {
        const res = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ fullName, email, password }),
        });

        const data = await res.json();

        if (!res.ok) {
          throw new Error(data.error?.message || 'Registration failed');
        }

        // Newly registered users are OWNER role by default -> redirect straight to My Documents dashboard
        router.push('/documents');
      } else {
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
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function fillCreds(cred: (typeof QUICK_CREDS)[0]) {
    setMode('login');
    setEmail(cred.email);
    setPassword(cred.pass);
    setError(null);
  }

  return (
    <div className="w-full max-w-md">
      {/* Brand Header */}
      <div className="text-center mb-8">
        <Link href="/" className="inline-flex justify-center mb-4">
          <TrustVaultLogo />
        </Link>
        <div className="eyebrow text-accent">■ ACCESS CONTROL GATEWAY</div>
        <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
          {mode === 'register' ? 'CREATE SECURE ACCOUNT' : 'AUTHENTICATE SESSION'}
        </h1>
      </div>

      {/* Tab Switcher */}
      <div className="flex border border-border-dark bg-ink-light rounded-t-md p-1 font-mono text-xs mb-[-1px] relative z-10">
        <button
          type="button"
          onClick={() => {
            setMode('login');
            setError(null);
          }}
          className={`flex-1 py-2 text-center rounded transition-colors uppercase font-bold flex items-center justify-center gap-1.5 ${
            mode === 'login'
              ? 'bg-accent text-white shadow'
              : 'text-paper-dark hover:text-paper hover:bg-ink'
          }`}
        >
          <Lock className="w-3.5 h-3.5" />
          <span>SIGN IN</span>
        </button>
        <button
          type="button"
          onClick={() => {
            setMode('register');
            setError(null);
          }}
          className={`flex-1 py-2 text-center rounded transition-colors uppercase font-bold flex items-center justify-center gap-1.5 ${
            mode === 'register'
              ? 'bg-accent text-white shadow'
              : 'text-paper-dark hover:text-paper hover:bg-ink'
          }`}
        >
          <UserPlus className="w-3.5 h-3.5" />
          <span>REGISTER (NEW USER)</span>
        </button>
      </div>

      {/* 1-Click Seed Credentials Selector (Visible in Sign In mode) */}
      {mode === 'login' && (
        <div className="bg-ink-light border border-border-dark border-t-0 p-4 font-mono text-xs">
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
      )}

      {/* Main Card */}
      <div className={`bg-ink-light border border-border-dark p-6 sm:p-8 rounded-b-md shadow-2xl ${mode === 'register' ? 'border-t-0' : 'border-t-0'}`}>
        {error && (
          <div className="mb-5 p-3 bg-denied/15 border border-denied/40 rounded flex items-start gap-2.5 text-xs text-paper font-mono">
            <ShieldAlert className="w-4 h-4 text-denied flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        {mode === 'register' && (
          <div className="mb-5 p-3 bg-accent/10 border border-accent/30 rounded flex items-start gap-2.5 text-xs text-paper font-mono">
            <CheckCircle2 className="w-4 h-4 text-accent flex-shrink-0 mt-0.5" />
            <span>
              Self-registered accounts receive <strong>OWNER</strong> role: your personal &quot;My Documents&quot; vault, upload capability, and sharing controls.
            </span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          {mode === 'register' && (
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-widest text-paper-dark/70 mb-1.5">
                Full Name
              </label>
              <div className="relative">
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="e.g. Chintu Patil"
                  className="w-full bg-ink border border-border-dark focus:border-accent px-3 py-2.5 pl-9 rounded text-sm text-paper placeholder-paper-dark/30 font-mono outline-none transition-colors"
                />
                <User className="w-4 h-4 text-paper-dark/40 absolute left-3 top-3" />
              </div>
            </div>
          )}

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-paper-dark/70 mb-1.5">
              {mode === 'register' ? 'Email Address (Gmail or Corporate)' : 'Email Address'}
            </label>
            <div className="relative">
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder={mode === 'register' ? 'you@gmail.com' : 'name@company.test'}
                className="w-full bg-ink border border-border-dark focus:border-accent px-3 py-2.5 pl-9 rounded text-sm text-paper placeholder-paper-dark/30 font-mono outline-none transition-colors"
              />
              <Mail className="w-4 h-4 text-paper-dark/40 absolute left-3 top-3" />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-paper-dark/70 mb-1.5">
              Password {mode === 'register' ? '(Min 8 chars, Argon2id)' : '(Argon2id Hashed)'}
            </label>
            <div className="relative">
              <input
                type="password"
                required
                minLength={mode === 'register' ? 8 : 1}
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
              <span>■ PROCESSING REQUEST...</span>
            ) : mode === 'register' ? (
              <>
                <span>■ CREATE ACCOUNT & OPEN VAULT</span>
                <ArrowRight className="w-4 h-4" />
              </>
            ) : (
              <>
                <span>■ SIGN IN TO VAULT</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        <div className="mt-5 text-center font-mono text-xs">
          {mode === 'login' ? (
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className="text-accent hover:underline inline-flex items-center gap-1"
            >
              Don&apos;t have an account? Register with your Gmail here →
            </button>
          ) : (
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className="text-accent hover:underline inline-flex items-center gap-1"
            >
              Already registered? Sign in with your credentials →
            </button>
          )}
        </div>

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
  );
}

export default function LoginPage() {
  return (
    <div className="min-h-screen bg-ink text-paper flex flex-col justify-center items-center p-4 font-sans selection:bg-accent selection:text-white">
      <Suspense fallback={<div className="font-mono text-xs text-paper-dark">Loading gateway...</div>}>
        <AuthForm />
      </Suspense>
    </div>
  );
}
