'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Upload,
  Search,
  FileText,
  Download,
  Trash2,
  Share2,
  Filter,
  CheckCircle2,
  Clock,
  Shield,
  Plus,
  RefreshCw,
  Folder,
} from 'lucide-react';

interface DocumentItem {
  id: string;
  title: string;
  originalFileName: string;
  mimeType: string;
  fileSize: number;
  category: string;
  folderPath: string;
  ownerName: string;
  ownerEmail: string;
  currentVersion: number;
  updatedAt: string;
}

export default function DocumentsPage() {
  const [documents, setDocuments] = useState<DocumentItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string>('');
  const [uploadModalOpen, setUploadModalOpen] = useState(false);

  // Upload Form State
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadTitle, setUploadTitle] = useState('');
  const [uploadCategory, setUploadCategory] = useState('FINANCIAL');
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  async function loadDocuments() {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      if (category) params.set('category', category);

      const res = await fetch(`/api/documents?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setDocuments(data.documents || []);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDocuments();
  }, [category]);

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    loadDocuments();
  }

  async function handleUploadSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!uploadFile) return;

    setUploading(true);
    setUploadError(null);

    try {
      const formData = new FormData();
      formData.append('file', uploadFile);
      formData.append('title', uploadTitle || uploadFile.name);
      formData.append('category', uploadCategory);

      const res = await fetch('/api/documents', {
        method: 'POST',
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error?.message || 'Upload failed');
      }

      setUploadModalOpen(false);
      setUploadFile(null);
      setUploadTitle('');
      loadDocuments();
    } catch (err: any) {
      setUploadError(err.message);
    } finally {
      setUploading(false);
    }
  }

  async function handleDelete(docId: string) {
    if (!confirm('Move this document to trash? Non-owners will immediately lose access.')) return;

    try {
      const res = await fetch(`/api/documents/${docId}`, { method: 'DELETE' });
      if (res.ok) {
        loadDocuments();
      }
    } catch (err) {
      console.error(err);
    }
  }

  const totalBytes = documents.reduce((acc, d) => acc + (d.fileSize || 0), 0);

  return (
    <div className="space-y-6">
      {/* Top Banner & Stats Strip */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-border-dark">
        <div>
          <span className="eyebrow text-accent">■ VAULT REPOSITORY</span>
          <h1 className="text-2xl font-display font-black uppercase tracking-tight text-paper mt-1">
            PROTECTED DOCUMENTS
          </h1>
        </div>

        <button
          onClick={() => setUploadModalOpen(true)}
          className="btn-industrial bg-accent hover:bg-accent-hover text-white px-4 py-2.5 rounded flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          <span>UPLOAD ENCRYPTED FILE</span>
        </button>
      </div>

      {/* Stats Strip */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono text-xs">
        <div className="p-4 bg-ink-light border border-border-dark rounded">
          <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">ACTIVE VAULT ASSETS</span>
          <div className="text-xl font-bold text-paper mt-1">{documents.length} Records</div>
        </div>
        <div className="p-4 bg-ink-light border border-border-dark rounded">
          <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">PRIVATE STORAGE ALLOCATED</span>
          <div className="text-xl font-bold text-paper mt-1">{(totalBytes / (1024 * 1024)).toFixed(2)} MB</div>
        </div>
        <div className="p-4 bg-ink-light border border-border-dark rounded">
          <span className="text-[10px] text-paper-dark/50 uppercase tracking-widest block">CENTRAL POLICY STATUS</span>
          <div className="text-xl font-bold text-allowed mt-1 flex items-center gap-1.5">
            <CheckCircle2 className="w-4 h-4" /> ENFORCING
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <form onSubmit={handleSearchSubmit} className="flex-1 relative">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by title, filename, or keyword..."
            className="w-full bg-ink-light border border-border-dark focus:border-accent px-4 py-2 pl-9 rounded text-xs font-mono text-paper placeholder-paper-dark/40 outline-none"
          />
          <Search className="w-4 h-4 text-paper-dark/40 absolute left-3 top-2.5" />
        </form>

        <div className="flex gap-2 font-mono text-xs">
          {['', 'FINANCIAL', 'LEGAL', 'TECHNICAL', 'CONFIDENTIAL'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={`px-3 py-1.5 border rounded uppercase text-[11px] transition-colors ${
                category === cat
                  ? 'bg-accent text-white border-accent font-bold'
                  : 'bg-ink-light border-border-dark text-paper-dark hover:border-paper/40'
              }`}
            >
              {cat || 'ALL'}
            </button>
          ))}
        </div>
      </div>

      {/* Documents Table */}
      <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden font-mono text-xs">
        {loading ? (
          <div className="py-16 text-center text-paper-dark/50">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-accent" />
            <span>Scanning vault index...</span>
          </div>
        ) : documents.length === 0 ? (
          <div className="py-16 text-center space-y-3">
            <div className="text-paper-dark/40 text-sm">No documents found matching current filter.</div>
            <button
              onClick={() => setUploadModalOpen(true)}
              className="px-4 py-2 bg-accent/20 text-accent border border-accent/40 rounded text-xs hover:bg-accent/30 font-bold"
            >
              Upload your first document
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-ink-dark border-b border-border-dark text-[10px] text-paper-dark/50 uppercase tracking-widest">
                <tr>
                  <th className="py-3 px-4">Document Title</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Version</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">Owner</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60">
                {documents.map((doc) => (
                  <tr key={doc.id} className="hover:bg-ink/40 transition-colors">
                    <td className="py-3.5 px-4">
                      <Link
                        href={`/documents/${doc.id}`}
                        className="font-bold text-paper hover:text-accent flex items-center gap-2 group"
                      >
                        <FileText className="w-4 h-4 text-accent" />
                        <span className="truncate group-hover:underline">{doc.title}</span>
                      </Link>
                      <span className="text-[10px] text-paper-dark/40 block mt-0.5">{doc.originalFileName}</span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-ink border border-border-dark text-paper-dark uppercase">
                        {doc.category}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-paper-dark">v{doc.currentVersion}</td>
                    <td className="py-3.5 px-4 text-paper-dark">{(doc.fileSize / 1024).toFixed(1)} KB</td>
                    <td className="py-3.5 px-4 text-paper-dark truncate">{doc.ownerName}</td>
                    <td className="py-3.5 px-4 text-right space-x-2">
                      <Link
                        href={`/documents/${doc.id}`}
                        className="px-2.5 py-1 bg-ink border border-border-dark hover:border-accent text-paper rounded text-[11px] inline-flex items-center gap-1"
                      >
                        <Share2 className="w-3.5 h-3.5" />
                        <span>SHARE</span>
                      </Link>
                      <a
                        href={`/api/documents/${doc.id}/download`}
                        className="px-2.5 py-1 bg-accent/15 border border-accent/40 text-accent hover:bg-accent/25 rounded text-[11px] inline-flex items-center gap-1 font-bold"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>DOWNLOAD</span>
                      </a>
                      <button
                        onClick={() => handleDelete(doc.id)}
                        className="p-1 hover:text-denied text-paper-dark/40 transition-colors"
                        title="Move to trash"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Upload Modal */}
      {uploadModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-ink border border-border-dark rounded-md max-w-lg w-full p-6 font-mono text-xs shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-border-dark mb-4">
              <span className="font-bold text-paper uppercase tracking-wider">■ UPLOAD ENCRYPTED DOCUMENT</span>
              <button
                onClick={() => setUploadModalOpen(false)}
                className="text-paper-dark hover:text-paper"
              >
                ✕
              </button>
            </div>

            {uploadError && (
              <div className="mb-4 p-3 bg-denied/15 border border-denied/40 text-denied rounded text-[11px]">
                {uploadError}
              </div>
            )}

            <form onSubmit={handleUploadSubmit} className="space-y-4">
              <div>
                <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                  File Attachment (Magic Bytes Inspected)
                </label>
                <input
                  type="file"
                  required
                  onChange={(e) => {
                    const f = e.target.files?.[0] || null;
                    setUploadFile(f);
                    if (f && !uploadTitle) {
                      setUploadTitle(f.name.replace(/\.[^/.]+$/, ''));
                    }
                  }}
                  className="w-full bg-ink-light border border-border-dark p-2 rounded text-paper file:mr-3 file:py-1 file:px-2 file:rounded file:border-0 file:text-[11px] file:font-mono file:bg-accent file:text-white"
                />
                <span className="text-[9px] text-paper-dark/40 mt-1 block">
                  Allowed: PDF, DOCX, XLSX, PPTX, PNG, JPG, CSV, TXT (Max 25 MB).
                </span>
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                  Document Title
                </label>
                <input
                  type="text"
                  required
                  value={uploadTitle}
                  onChange={(e) => setUploadTitle(e.target.value)}
                  placeholder="e.g. Q3 Audited Balance Sheet"
                  className="w-full bg-ink-light border border-border-dark focus:border-accent p-2 rounded text-paper outline-none"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                  Classification Category
                </label>
                <select
                  value={uploadCategory}
                  onChange={(e) => setUploadCategory(e.target.value)}
                  className="w-full bg-ink-light border border-border-dark focus:border-accent p-2 rounded text-paper outline-none"
                >
                  <option value="FINANCIAL">FINANCIAL</option>
                  <option value="LEGAL">LEGAL</option>
                  <option value="TECHNICAL">TECHNICAL</option>
                  <option value="EXECUTIVE">EXECUTIVE</option>
                  <option value="CONFIDENTIAL">CONFIDENTIAL</option>
                  <option value="OTHER">OTHER</option>
                </select>
              </div>

              <div className="pt-4 border-t border-border-dark flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setUploadModalOpen(false)}
                  className="px-4 py-2 border border-border-dark rounded hover:bg-ink-light text-paper-dark"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  disabled={uploading}
                  className="btn-industrial bg-accent hover:bg-accent-hover text-white px-5 py-2 rounded font-bold disabled:opacity-50"
                >
                  {uploading ? 'ENCRYPTING & UPLOADING...' : '■ CONFIRM UPLOAD'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
