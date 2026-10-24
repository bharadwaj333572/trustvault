'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { TrustVaultLogo } from '@/components/ui/logo';
import {
  FileText,
  Share2,
  Trash2,
  ShieldCheck,
  Users,
  AlertTriangle,
  LogOut,
  Search,
  Moon,
  Sun,
  Menu,
  X,
  Lock,
} from 'lucide-react';

interface CurrentUser {
  id: string;
  email: string;
  fullName: string;
  role: 'ADMIN' | 'OWNER' | 'VIEWER';
}

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<CurrentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(true);

  useEffect(() => {
    async function loadUser() {
      try {
        const res = await fetch('/api/auth/me');
        if (!res.ok) {
          router.push('/login');
          return;
        }
        const data = await res.json();
        setUser(data.user);
      } catch {
        router.push('/login');
      } finally {
        setLoading(false);
      }
    }
    loadUser();
  }, [router]);

  async function handleLogout() {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.push('/login');
  }

  function toggleTheme() {
    const next = !darkMode;
    setDarkMode(next);
    if (next) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-ink text-paper flex items-center justify-center font-mono text-xs">
        <div className="flex items-center gap-2 text-accent">
          <span className="w-2 h-2 bg-accent animate-ping rounded-full" />
          <span>INITIALIZING SECURE SESSION...</span>
        </div>
      </div>
    );
  }

  const role = user?.role || 'VIEWER';

  return (
    <div className={`min-h-screen flex bg-ink text-paper font-sans ${darkMode ? 'dark' : ''}`}>
      {/* Sidebar - Desktop */}
      <aside className="hidden md:flex flex-col w-64 border-r border-border-dark bg-ink-dark/80 flex-shrink-0">
        <div className="h-16 px-6 flex items-center border-b border-border-dark">
          <Link href="/">
            <TrustVaultLogo className="h-6" />
          </Link>
        </div>

        {/* User Info Strip */}
        <div className="p-4 border-b border-border-dark bg-ink-light/40 font-mono text-xs">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest">SESSION ROLE</span>
            <span
              className={`px-1.5 py-0.5 text-[9px] font-bold rounded uppercase ${
                role === 'ADMIN'
                  ? 'bg-accent/20 text-accent border border-accent/40'
                  : role === 'OWNER'
                  ? 'bg-paper/20 text-paper border border-paper/40'
                  : 'bg-allowed/20 text-allowed border border-allowed/40'
              }`}
            >
              {role}
            </span>
          </div>
          <div className="font-semibold text-paper truncate mt-1">{user?.fullName}</div>
          <div className="text-[10px] text-paper-dark/60 truncate">{user?.email}</div>
        </div>

        {/* Navigation Items (Role-Aware) */}
        <nav className="flex-1 p-4 space-y-1 font-mono text-xs">
          {/* Owner & Viewer shared links */}
          {(role === 'OWNER' || role === 'ADMIN') && (
            <Link
              href="/documents"
              className={`flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
                pathname === '/documents'
                  ? 'bg-accent text-white font-bold'
                  : 'text-paper-dark hover:bg-ink-light hover:text-paper'
              }`}
            >
              <FileText className="w-4 h-4" />
              <span>MY DOCUMENTS</span>
            </Link>
          )}

          <Link
            href="/shared"
            className={`flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
              pathname === '/shared'
                ? 'bg-accent text-white font-bold'
                : 'text-paper-dark hover:bg-ink-light hover:text-paper'
            }`}
          >
            <Share2 className="w-4 h-4" />
            <span>SHARED WITH ME</span>
          </Link>

          {role === 'OWNER' && (
            <Link
              href="/documents?trash=true"
              className={`flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
                pathname.includes('trash=true')
                  ? 'bg-accent text-white font-bold'
                  : 'text-paper-dark hover:bg-ink-light hover:text-paper'
              }`}
            >
              <Trash2 className="w-4 h-4" />
              <span>TRASH / RESTORE</span>
            </Link>
          )}

          {/* Admin Specific Links */}
          {role === 'ADMIN' && (
            <>
              <div className="pt-4 pb-1 text-[10px] text-paper-dark/40 uppercase tracking-widest px-3">
                CUSTODIAN TOOLS
              </div>

              <Link
                href="/admin"
                className={`flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
                  pathname === '/admin'
                    ? 'bg-accent text-white font-bold'
                    : 'text-paper-dark hover:bg-ink-light hover:text-paper'
                }`}
              >
                <ShieldCheck className="w-4 h-4" />
                <span>INTEGRITY STATUS</span>
              </Link>

              <Link
                href="/admin/audit"
                className={`flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
                  pathname === '/admin/audit'
                    ? 'bg-accent text-white font-bold'
                    : 'text-paper-dark hover:bg-ink-light hover:text-paper'
                }`}
              >
                <Lock className="w-4 h-4" />
                <span>GLOBAL AUDIT LOG</span>
              </Link>

              <Link
                href="/admin/alerts"
                className={`flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
                  pathname === '/admin/alerts'
                    ? 'bg-accent text-white font-bold'
                    : 'text-paper-dark hover:bg-ink-light hover:text-paper'
                }`}
              >
                <AlertTriangle className="w-4 h-4" />
                <span>SECURITY ALERTS</span>
              </Link>

              <Link
                href="/admin/users"
                className={`flex items-center gap-2.5 px-3 py-2 rounded transition-colors ${
                  pathname === '/admin/users'
                    ? 'bg-accent text-white font-bold'
                    : 'text-paper-dark hover:bg-ink-light hover:text-paper'
                }`}
              >
                <Users className="w-4 h-4" />
                <span>USER DIRECTORY</span>
              </Link>
            </>
          )}
        </nav>

        {/* Logout Bottom Button */}
        <div className="p-4 border-t border-border-dark">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 text-xs font-mono text-paper-dark/70 hover:text-denied hover:bg-denied/10 rounded transition-colors"
          >
            <LogOut className="w-4 h-4" />
            <span>TERMINATE SESSION</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-y-auto">
        {/* Top Bar */}
        <header className="h-16 border-b border-border-dark bg-ink/70 backdrop-blur px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 text-paper-dark hover:text-paper"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
            <span className="hidden sm:inline font-mono text-[11px] text-paper-dark/60 uppercase tracking-widest">
              ■ {pathname.replace('/', '').toUpperCase() || 'VAULT'}
            </span>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={toggleTheme}
              className="p-2 text-paper-dark hover:text-paper rounded border border-border-dark hover:border-paper/40 transition-colors"
              title="Toggle theme"
            >
              {darkMode ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            <span className="font-mono text-xs font-bold text-accent px-2.5 py-1 bg-ink-light border border-border-dark rounded">
              ■ {user?.role}
            </span>
          </div>
        </header>

        {/* Content Body */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  );
}
