import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Readable } from 'stream';
import { MAX_FILE_SIZE_BYTES } from '../validation/upload';
import { AppError } from '../errors';

export interface StorageWriteResult {
  storageKey: string;
  sha256Checksum: string;
  byteLength: number;
}

export class FileStorageAdapter {
  private readonly storageDir: string;

  constructor(customDir?: string) {
    this.storageDir = customDir || process.env.STORAGE_DIR || path.resolve(process.cwd(), 'storage');
    if (!fs.existsSync(this.storageDir)) {
      fs.mkdirSync(this.storageDir, { recursive: true });
    }
  }

  /**
   * Persists a file buffer into private storage under an opaque random UUID.
   * Calculates SHA-256 checksum and verifies size limits.
   */
  async writeBuffer(buffer: Buffer): Promise<StorageWriteResult> {
    if (buffer.length > MAX_FILE_SIZE_BYTES) {
      throw new AppError({
        code: 'FILE_TOO_LARGE',
        statusCode: 413,
        message: 'File size exceeds maximum allowable limit of 25 MB.',
      });
    }

    const storageKey = crypto.randomUUID();
    const targetPath = path.join(this.storageDir, storageKey);

    const hash = crypto.createHash('sha256');
    hash.update(buffer);
    const sha256Checksum = hash.digest('hex');

    await fs.promises.writeFile(targetPath, buffer);

    return {
      storageKey,
      sha256Checksum,
      byteLength: buffer.length,
    };
  }

  /**
   * Creates a readable stream for an existing file.
   * Supports optional range queries (start, end).
   */
  createReadStream(storageKey: string, range?: { start: number; end: number }): fs.ReadStream {
    // Defend against path traversal in storage keys
    const sanitizedKey = path.basename(storageKey);
    const targetPath = path.join(this.storageDir, sanitizedKey);

    if (!fs.existsSync(targetPath)) {
      throw new AppError({
        code: 'NOT_FOUND',
        statusCode: 404,
        message: 'Underlying storage object not found.',
      });
    }

    return fs.createReadStream(targetPath, range);
  }

  /**
   * Reads the full file as a Buffer.
   */
  async readBuffer(storageKey: string): Promise<Buffer> {
    const sanitizedKey = path.basename(storageKey);
    const targetPath = path.join(this.storageDir, sanitizedKey);

    if (!fs.existsSync(targetPath)) {
      throw new AppError({
        code: 'NOT_FOUND',
        statusCode: 404,
        message: 'Underlying storage object not found.',
      });
    }

    return fs.promises.readFile(targetPath);
  }

  /**
   * Gets file metadata (file size) from disk.
   */
  async getStat(storageKey: string): Promise<fs.Stats> {
    const sanitizedKey = path.basename(storageKey);
    const targetPath = path.join(this.storageDir, sanitizedKey);

    if (!fs.existsSync(targetPath)) {
      throw new AppError({
        code: 'NOT_FOUND',
        statusCode: 404,
        message: 'Underlying storage object not found.',
      });
    }

    return fs.promises.stat(targetPath);
  }

  /**
   * Deletes a file from disk.
   */
  async deleteFile(storageKey: string): Promise<void> {
    const sanitizedKey = path.basename(storageKey);
    const targetPath = path.join(this.storageDir, sanitizedKey);
    if (fs.existsSync(targetPath)) {
      await fs.promises.unlink(targetPath);
    }
  }
}

export const fileStorage = new FileStorageAdapter();
