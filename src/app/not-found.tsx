import React from 'react';
import Link from 'next/link';
import { TrustVaultLogo } from '@/components/ui/logo';
import { ArrowLeft, ShieldAlert } from 'lucide-react';

export default function NotFoundPage() {
  return (
    <div className="min-h-screen bg-ink text-paper flex flex-col justify-center items-center p-4 font-mono text-xs selection:bg-accent selection:text-white">
      <div className="w-full max-w-md text-center space-y-6">
        <div className="flex justify-center">
          <TrustVaultLogo />
        </div>

        <div className="p-8 bg-ink-light border border-border-dark rounded-md shadow-2xl space-y-4">
          <div className="w-12 h-12 rounded-full bg-accent/15 border border-accent/40 flex items-center justify-center mx-auto text-accent">
            <ShieldAlert className="w-6 h-6" />
          </div>

          <div className="text-3xl font-display font-black text-paper uppercase tracking-tight">
            404 NOT FOUND
          </div>

          <p className="text-paper-dark/70 text-xs leading-relaxed">
            The requested document or resource does not exist, or your session does not possess the explicit authorization grant required to access it.
          </p>

          <div className="p-3 bg-ink border border-border-dark rounded text-[10px] text-paper-dark/50 text-left">
            ■ SECURITY GUARANTEE: In accordance with zero-trust isolation policies, non-existent and ungranted resources emit identical response payloads to prevent metadata existence leakage.
          </div>

          <div className="pt-2">
            <Link
              href="/"
              className="w-full py-2.5 bg-accent hover:bg-accent-hover text-white font-bold rounded flex items-center justify-center gap-2 transition-transform active:translate-y-0.5"
            >
              <ArrowLeft className="w-4 h-4" />
              <span>RETURN TO VAULT</span>
            </Link>
          </div>
        </div>

        <div className="text-[10px] text-paper-dark/40">
          TrustVault Cryptographic Gateway • Zero-Trust Policy
        </div>
      </div>
    </div>
  );
}
