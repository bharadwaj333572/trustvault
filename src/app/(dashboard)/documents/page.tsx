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
  FolderInput,
  ChevronLeft,
  ChevronRight,
  CheckSquare,
  Square,
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
  const [selectedFolder, setSelectedFolder] = useState<string>('');
  const [uploadModalOpen, setUploadModalOpen] = useState(false);

  // Pagination State
  const [page, setPage] = useState(1);
  const pageSize = 8;

  // Bulk Selection State
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkActionLoading, setBulkActionLoading] = useState(false);
  const [bulkMoveFolder, setBulkMoveFolder] = useState('/contracts');

  // Upload Form State
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadTitle, setUploadTitle] = useState('');
  const [uploadCategory, setUploadCategory] = useState('FINANCIAL');
  const [uploadFolder, setUploadFolder] = useState('/');
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
    setPage(1);
    setSelectedIds(new Set());
  }, [category]);

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    loadDocuments();
  }

  // Filter documents by folder client-side if selected
  const filteredDocuments = documents.filter((d) => {
    if (selectedFolder && d.folderPath !== selectedFolder) return false;
    return true;
  });

  // Extract unique folders
  const allFolders = Array.from(new Set(documents.map((d) => d.folderPath || '/')));

  // Pagination slice
  const totalPages = Math.max(1, Math.ceil(filteredDocuments.length / pageSize));
  const paginatedDocs = filteredDocuments.slice((page - 1) * pageSize, page * pageSize);

  function toggleSelectAll() {
    if (selectedIds.size === paginatedDocs.length && paginatedDocs.length > 0) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(paginatedDocs.map((d) => d.id)));
    }
  }

  function toggleSelectId(id: string) {
    const next = new Set(selectedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setSelectedIds(next);
  }

  async function handleBulkDelete() {
    if (!confirm(`Are you sure you want to move ${selectedIds.size} documents to trash?`)) return;
    setBulkActionLoading(true);
    try {
      const res = await fetch('/api/documents/bulk', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          action: 'delete',
          documentIds: Array.from(selectedIds),
        }),
      });
      if (res.ok) {
        setSelectedIds(new Set());
        await loadDocuments();
      }
    } finally {
      setBulkActionLoading(false);
    }
  }

  async function handleBulkMove() {
    setBulkActionLoading(true);
    try {
      const res = await fetch('/api/documents/bulk', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          action: 'move',
          documentIds: Array.from(selectedIds),
          folderPath: bulkMoveFolder,
        }),
      });
      if (res.ok) {
        setSelectedIds(new Set());
        await loadDocuments();
      }
    } finally {
      setBulkActionLoading(false);
    }
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
      formData.append('folderPath', uploadFolder.trim() || '/');

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
      setUploadFolder('/');
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

      {/* Folders & Categories Tabs */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 bg-ink-dark/60 p-3 border border-border-dark rounded font-mono text-xs">
        {/* Category Filter Chips */}
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-[10px] text-paper-dark/50 uppercase mr-1">CATEGORY:</span>
          {['', 'FINANCIAL', 'LEGAL', 'TECHNICAL', 'CONFIDENTIAL'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className={`px-2.5 py-1 border rounded uppercase text-[10px] transition-colors ${
                category === cat
                  ? 'bg-accent text-white border-accent font-bold'
                  : 'bg-ink border-border-dark text-paper-dark hover:border-paper/40'
              }`}
            >
              {cat || 'ALL'}
            </button>
          ))}
        </div>

        {/* Folder Filter Dropdown */}
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-paper-dark/50 uppercase flex items-center gap-1">
            <Folder className="w-3 h-3 text-accent" /> FOLDER:
          </span>
          <select
            value={selectedFolder}
            onChange={(e) => setSelectedFolder(e.target.value)}
            className="bg-ink border border-border-dark text-paper px-2 py-1 text-xs outline-none"
          >
            <option value="">ALL FOLDERS</option>
            {allFolders.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <form onSubmit={handleSearchSubmit} className="relative">
        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search by title, filename, or keyword..."
          className="w-full bg-ink-light border border-border-dark focus:border-accent px-4 py-2 pl-9 rounded text-xs font-mono text-paper placeholder-paper-dark/40 outline-none"
        />
        <Search className="w-4 h-4 text-paper-dark/40 absolute left-3 top-2.5" />
      </form>

      {/* Bulk Action Strip (Appears when >= 1 document is selected) */}
      {selectedIds.size > 0 && (
        <div className="p-3 bg-accent/10 border border-accent rounded flex flex-wrap items-center justify-between gap-3 font-mono text-xs animate-in fade-in duration-200">
          <div className="flex items-center gap-2 text-accent font-bold">
            <CheckSquare className="w-4 h-4" />
            <span>SELECTED {selectedIds.size} ASSETS</span>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1">
              <input
                type="text"
                value={bulkMoveFolder}
                onChange={(e) => setBulkMoveFolder(e.target.value)}
                placeholder="/target-folder"
                className="bg-ink border border-border-dark px-2 py-1 text-xs text-paper w-36 outline-none"
              />
              <button
                onClick={handleBulkMove}
                disabled={bulkActionLoading}
                className="px-3 py-1 bg-ink border border-border-dark hover:border-accent text-paper text-xs flex items-center gap-1"
              >
                <FolderInput className="w-3.5 h-3.5" />
                <span>MOVE</span>
              </button>
            </div>

            <button
              onClick={handleBulkDelete}
              disabled={bulkActionLoading}
              className="px-3 py-1 bg-denied/15 border border-denied text-denied hover:bg-denied hover:text-white text-xs font-bold flex items-center gap-1"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>DELETE SELECTED</span>
            </button>
          </div>
        </div>
      )}

      {/* Documents Table */}
      <div className="border border-border-dark rounded-md bg-ink-light overflow-hidden font-mono text-xs">
        {loading ? (
          <div className="py-16 text-center text-paper-dark/50">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-accent" />
            <span>Scanning vault index...</span>
          </div>
        ) : filteredDocuments.length === 0 ? (
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
                  <th className="py-3 px-3 w-8">
                    <button onClick={toggleSelectAll} className="hover:text-paper">
                      {selectedIds.size === paginatedDocs.length && paginatedDocs.length > 0 ? (
                        <CheckSquare className="w-4 h-4 text-accent" />
                      ) : (
                        <Square className="w-4 h-4 text-paper-dark/40" />
                      )}
                    </button>
                  </th>
                  <th className="py-3 px-4">Document Title</th>
                  <th className="py-3 px-4">Folder</th>
                  <th className="py-3 px-4">Category</th>
                  <th className="py-3 px-4">Version</th>
                  <th className="py-3 px-4">Size</th>
                  <th className="py-3 px-4">Owner</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-dark/60">
                {paginatedDocs.map((doc) => {
                  const isSelected = selectedIds.has(doc.id);
                  return (
                    <tr
                      key={doc.id}
                      className={`hover:bg-ink/40 transition-colors ${isSelected ? 'bg-accent/5' : ''}`}
                    >
                      <td className="py-3.5 px-3">
                        <button onClick={() => toggleSelectId(doc.id)} className="hover:text-paper">
                          {isSelected ? (
                            <CheckSquare className="w-4 h-4 text-accent" />
                          ) : (
                            <Square className="w-4 h-4 text-paper-dark/40" />
                          )}
                        </button>
                      </td>
                      <td className="py-3.5 px-4">
                        <Link
                          href={`/documents/${doc.id}`}
                          className="font-bold text-paper hover:text-accent flex items-center gap-2 group"
                        >
                          <FileText className="w-4 h-4 text-accent flex-shrink-0" />
                          <span className="truncate group-hover:underline">{doc.title}</span>
                        </Link>
                        <span className="text-[10px] text-paper-dark/40 block mt-0.5">{doc.originalFileName}</span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="text-[10px] text-paper-dark/70 font-mono flex items-center gap-1">
                          <Folder className="w-3 h-3 text-paper-dark/40" />
                          {doc.folderPath || '/'}
                        </span>
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
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {filteredDocuments.length > pageSize && (
          <div className="p-3 bg-ink-dark border-t border-border-dark flex items-center justify-between text-xs font-mono text-paper-dark/70">
            <span>
              SHOWING {(page - 1) * pageSize + 1} - {Math.min(page * pageSize, filteredDocuments.length)} OF{' '}
              {filteredDocuments.length}
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="px-2.5 py-1 bg-ink border border-border-dark hover:border-paper disabled:opacity-30 disabled:pointer-events-none rounded flex items-center gap-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>PREV</span>
              </button>
              <span className="px-2 text-paper font-bold">
                {page} / {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="px-2.5 py-1 bg-ink border border-border-dark hover:border-paper disabled:opacity-30 disabled:pointer-events-none rounded flex items-center gap-1"
              >
                <span>NEXT</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
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

              <div className="grid grid-cols-2 gap-3">
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

                <div>
                  <label className="block text-[10px] uppercase tracking-widest text-paper-dark/60 mb-1">
                    Folder Path
                  </label>
                  <input
                    type="text"
                    value={uploadFolder}
                    onChange={(e) => setUploadFolder(e.target.value)}
                    placeholder="/contracts"
                    className="w-full bg-ink-light border border-border-dark focus:border-accent p-2 rounded text-paper outline-none"
                  />
                </div>
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
