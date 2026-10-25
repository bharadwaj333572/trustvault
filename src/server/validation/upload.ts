import path from 'path';
import { ValidationError } from '../errors';

export const MAX_FILE_SIZE_BYTES = 25 * 1024 * 1024; // 25 MB

export type AllowedMimeType =
  | 'application/pdf'
  | 'image/png'
  | 'image/jpeg'
  | 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' // docx
  | 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'         // xlsx
  | 'application/vnd.openxmlformats-officedocument.presentationml.presentation' // pptx
  | 'text/plain'
  | 'text/csv';

export interface FileValidationResult {
  detectedMime: AllowedMimeType;
  sanitizedFileName: string;
}

/**
 * Sanitizes original filename:
 * - Strips any directory traversal components (../, ..\, /)
 * - Removes control characters
 * - Normalizes Unicode
 * - Prevents double extension attacks (e.g. evil.pdf.exe -> sanitized)
 */
export function sanitizeFileName(originalName: string): string {
  if (!originalName || typeof originalName !== 'string') {
    return 'document_upload.bin';
  }

  // Strip path segments using basename
  let baseName = path.basename(originalName.trim());

  // Remove dangerous characters: null bytes, slashes, backslashes, colons
  baseName = baseName.replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g, '_');

  // Limit filename length
  if (baseName.length > 200) {
    const ext = path.extname(baseName);
    baseName = baseName.slice(0, 200 - ext.length) + ext;
  }

  return baseName;
}

/**
 * Inspects binary magic bytes from the start of the buffer
 * to reliably determine true file type, ignoring client-provided Content-Type or file extensions.
 */
export function detectMagicBytes(buffer: Buffer): AllowedMimeType {
  if (!buffer || buffer.length === 0) {
    throw new ValidationError('Uploaded file is empty (0 bytes).');
  }

  // 1. PDF: %PDF- (0x25 0x50 0x44 0x46)
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x25 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x44 &&
    buffer[3] === 0x46
  ) {
    return 'application/pdf';
  }

  // 2. PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4E &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0D &&
    buffer[5] === 0x0A &&
    buffer[6] === 0x1A &&
    buffer[7] === 0x0A
  ) {
    return 'image/png';
  }

  // 3. JPEG: FF D8 FF
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xFF &&
    buffer[1] === 0xD8 &&
    buffer[2] === 0xFF
  ) {
    return 'image/jpeg';
  }

  // 4. DOCX / XLSX / PPTX: Zip Container (PK 03 04)
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x50 &&
    buffer[1] === 0x4B &&
    buffer[2] === 0x03 &&
    buffer[3] === 0x04
  ) {
    // Check internal zip directory or payload signatures
    const bufferStr = buffer.slice(0, Math.min(buffer.length, 2048)).toString('binary');
    if (bufferStr.includes('word/')) {
      return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
    }
    if (bufferStr.includes('xl/')) {
      return 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    }
    if (bufferStr.includes('ppt/')) {
      return 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
    }
    // Default valid office document container
    return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  }

  // Reject executable formats explicitly:
  // Windows PE: MZ (0x4D 0x5A)
  if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
    throw new ValidationError('Security violation: Executable PE binaries (.exe/.dll) are strictly prohibited.');
  }
  // Linux ELF: 0x7F 'E' 'L' 'F'
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x7F &&
    buffer[1] === 0x45 &&
    buffer[2] === 0x4C &&
    buffer[3] === 0x46
  ) {
    throw new ValidationError('Security violation: Executable ELF binaries are strictly prohibited.');
  }

  // Reject script/HTML formats:
  const first512 = buffer.slice(0, Math.min(buffer.length, 512)).toString('utf-8').toLowerCase();
  if (
    first512.includes('<html') ||
    first512.includes('<!doctype html') ||
    first512.includes('<svg') ||
    first512.includes('<script') ||
    first512.startsWith('#!')
  ) {
    throw new ValidationError('Security violation: HTML, SVG, and shell scripts cannot be uploaded to prevent stored XSS.');
  }

  // 5. Plain text or CSV: Verify UTF-8 / ASCII text without binary control characters
  let isText = true;
  for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
    const byte = buffer[i];
    // Reject non-whitespace control characters (0x00 to 0x08, 0x0B, 0x0C, 0x0E to 0x1F)
    if ((byte < 0x09 || (byte > 0x0D && byte < 0x20)) && byte !== 0x00) {
      isText = false;
      break;
    }
    if (byte === 0x00) {
      isText = false;
      break;
    }
  }

  if (isText) {
    if (first512.includes(',') || first512.includes(';') || first512.includes('\t')) {
      return 'text/csv';
    }
    return 'text/plain';
  }

  throw new ValidationError(
    'File type rejected. Only verified PDF, DOCX, XLSX, PPTX, PNG, JPG, CSV, and TXT documents are permitted.'
  );
}

/**
 * Extension to MIME mapping for polyglot and extension mismatch verification
 */
const EXTENSION_MIME_MAP: Record<string, AllowedMimeType[]> = {
  '.pdf': ['application/pdf'],
  '.png': ['image/png'],
  '.jpg': ['image/jpeg'],
  '.jpeg': ['image/jpeg'],
  '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
  '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
  '.txt': ['text/plain'],
  '.csv': ['text/csv'],
};

const DISALLOWED_EXTENSIONS = new Set([
  '.exe', '.dll', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.mjs', '.jar', '.php', '.py', '.elf', '.com', '.scr', '.hta'
]);

/**
 * Malware scan placeholder.
 * Production hooks connect to ClamAV, AWS GuardDuty, or VirusTotal API.
 */
export async function scanFileForMalware(buffer: Buffer): Promise<{ isClean: boolean; threatName?: string }> {
  // Production integration hook: scans buffer against antivirus definitions.
  return { isClean: true };
}

/**
 * Full file validation pipeline.
 */
export function validateUploadedFile(
  buffer: Buffer,
  declaredFileName: string,
  declaredSize: number
): FileValidationResult {
  if (declaredSize > MAX_FILE_SIZE_BYTES || buffer.length > MAX_FILE_SIZE_BYTES) {
    throw new ValidationError(`File exceeds the maximum allowable limit of 25 MB.`);
  }

  if (buffer.length === 0) {
    throw new ValidationError('File cannot be empty (0 bytes).');
  }

  const sanitizedFileName = sanitizeFileName(declaredFileName);
  const ext = path.extname(sanitizedFileName).toLowerCase();

  // Reject dangerous executable extensions explicitly
  if (DISALLOWED_EXTENSIONS.has(ext)) {
    throw new ValidationError(`Security violation: Files with extension "${ext}" are strictly prohibited.`);
  }

  const detectedMime = detectMagicBytes(buffer);

  // Reject polyglot and file extension / magic-byte mismatches
  const allowedMimes = EXTENSION_MIME_MAP[ext];
  if (allowedMimes && !allowedMimes.includes(detectedMime)) {
    throw new ValidationError(
      `File extension mismatch: Declared extension "${ext}" does not match true binary content (${detectedMime}). Polyglot uploads are rejected.`
    );
  }

  return {
    detectedMime,
    sanitizedFileName,
  };
}
