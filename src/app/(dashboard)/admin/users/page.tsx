'use client';

import React, { useState, useEffect } from 'react';
import { Users, Shield, Lock, AlertTriangle, RefreshCw, CheckCircle2, XCircle } from 'lucide-react';

interface UserDirectoryItem {
  id: string;
  email: string;
  fullName: string;
  role: 'ADMIN' | 'OWNER' | 'VIEWER';
  isDisabled: boolean;
  failedLoginAttempts: number;
  lockedUntil: string | null;
  createdAt: string;
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState<UserDirectoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [updatingId, setUpdatingId] = useState<string | null>(null);

  async function loadUsers() {
    setLoading(true);
    try {
      const res = await fetch('/api/admin/users');
      if (res.ok) {
        const data = await res.json();
        setUsers(data.users || []);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function handleRoleChange(userId: string, newRole: string) {
    setUpdatingId(userId);
    try {
      const res = await fetch(`/api/admin/users/${userId}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ role: newRole }),
      });
      if (res.ok) {
        loadUsers();
      }
    } finally {
      setUpdatingId(null);
    }
  }

  async function handleToggleDisable(userId: string, currentDisabled: boolean, userEmail: string) {
    const nextState = !currentDisabled;
    if (nextState) {
      const confirmed = confirm(
        `Disable account for ${userEmail}?\n\nCONSEQUENCE: All active sessions will be terminated immediately. The user will be blocked on their very next request.`
      );
      if (!confirmed) return;
    }

    setUpdatingId(userId);
    try {
      const res = await fetch(`/api/admin/users/${userId}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ isDisabled: nextState }),
      });
      if (res.ok) {
        loadUsers();
      }
    } finally {
      setUpdatingId(null);
    }
  }

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border-dark">
        <div>
          <span className="eyebrow text-accent">■ ACCESS CONTROLLER</span>
          <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
            USER DIRECTORY & LIFECYCLE
          </h1>
        </div>

        <button
          onClick={loadUsers}
          className="btn-industrial bg-ink-light border border-border-dark px-3 py-2 rounded text-paper hover:border-paper/40 flex items-center gap-1.5"
        >
          <RefreshCw className="w-3.5 h-3.5" /> REFRESH LIST
        </button>
      </div>

      <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-paper-dark/50">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-accent" />
            <span>Scanning directory...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-ink-dark border-b border-border-dark text-[10px] text-paper-dark/50 uppercase tracking-widest">
                <tr>
                  <th className="py-3 px-4">User Details</th>
                  <th className="py-3 px-4">Role Assignment</th>
                  <th className="py-3 px-4">Account Status</th>
                  <th className="py-3 px-4">Failed Logins</th>
                  <th className="py-3 px-4 text-right">Emergency Controls</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60">
                {users.map((u) => (
                  <tr key={u.id} className={u.isDisabled ? 'bg-denied/5' : 'hover:bg-ink/40'}>
                    <td className="py-3.5 px-4">
                      <span className="font-bold text-paper block">{u.fullName}</span>
                      <span className="text-[10px] text-paper-dark/50">{u.email}</span>
                    </td>
                    <td className="py-3.5 px-4">
                      <select
                        value={u.role}
                        disabled={updatingId === u.id}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="bg-ink border border-border-dark px-2.5 py-1 rounded text-accent font-bold outline-none"
                      >
                        <option value="VIEWER">VIEWER</option>
                        <option value="OWNER">OWNER</option>
                        <option value="ADMIN">ADMIN</option>
                      </select>
                    </td>
                    <td className="py-3.5 px-4">
                      {u.isDisabled ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-denied/20 text-denied border border-denied/40 uppercase">
                          DISABLED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-allowed/20 text-allowed border border-allowed/40 uppercase">
                          ACTIVE
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-paper-dark">
                      {u.failedLoginAttempts > 0 ? (
                        <span className="text-denied font-bold">{u.failedLoginAttempts} attempts</span>
                      ) : (
                        '0'
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={() => handleToggleDisable(u.id, u.isDisabled, u.email)}
                        disabled={updatingId === u.id}
                        className={`px-3 py-1 rounded text-[11px] font-bold border transition-colors ${
                          u.isDisabled
                            ? 'bg-allowed/15 border-allowed/40 text-allowed hover:bg-allowed/25'
                            : 'bg-denied/15 border-denied/40 text-denied hover:bg-denied/25'
                        }`}
                      >
                        {u.isDisabled ? 'ENABLE ACCOUNT' : 'DISABLE ACCOUNT'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
