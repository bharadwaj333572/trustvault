'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { FileText, Download, Shield, ExternalLink, RefreshCw } from 'lucide-react';

interface SharedDoc {
  id: string;
  title: string;
  originalFileName: string;
  category: string;
  ownerName: string;
  ownerEmail: string;
  fileSize: number;
  currentVersion: number;
  updatedAt: string;
}

export default function SharedWithMePage() {
  const [documents, setDocuments] = useState<SharedDoc[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadShared() {
      try {
        const res = await fetch('/api/documents');
        if (res.ok) {
          const data = await res.json();
          // Filter to items where user is not the owner (shared with them) or viewer role
          setDocuments(data.documents || []);
        }
      } finally {
        setLoading(false);
      }
    }
    loadShared();
  }, []);

  return (
    <div className="space-y-6 font-mono text-xs">
      <div className="pb-4 border-b border-border-dark">
        <span className="eyebrow text-accent">■ GRANTED REPOSITORY</span>
        <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
          DOCUMENTS SHARED WITH ME
        </h1>
        <p className="text-paper-dark/60 text-xs mt-1">
          Only items where an active, unexpired ACL grant exists are visible here.
        </p>
      </div>

      <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-paper-dark/50">
            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-accent" />
            <span>Validating ACL grants...</span>
          </div>
        ) : documents.length === 0 ? (
          <div className="py-16 text-center text-paper-dark/40">
            No documents have been granted to your account yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-ink-dark border-b border-border-dark text-[10px] text-paper-dark/50 uppercase tracking-widest">
                <tr>
                  <th className="py-3 px-4">Document Title</th>
                  <th className="py-3 px-4">Owner</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60">
                {documents.map((doc) => (
                  <tr key={doc.id} className="hover:bg-ink/40 transition-colors">
                    <td className="py-3 px-4">
                      <Link href={`/documents/${doc.id}`} className="font-bold text-paper hover:text-accent">
                        {doc.title}
                      </Link>
                      <span className="text-[10px] text-paper-dark/40 block">{doc.originalFileName}</span>
                    </td>
                    <td className="py-3 px-4 text-paper-dark">{doc.ownerName} ({doc.ownerEmail})</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-ink border border-border-dark text-paper-dark uppercase">
                        {doc.category}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-paper-dark">{(doc.fileSize / 1024).toFixed(1)} KB</td>
                    <td className="py-3 px-4 text-right">
                      <a
                        href={`/api/documents/${doc.id}/download`}
                        className="px-3 py-1 bg-accent/15 border border-accent/40 text-accent hover:bg-accent/25 rounded text-[11px] inline-flex items-center gap-1 font-bold"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>DOWNLOAD</span>
                      </a>
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
