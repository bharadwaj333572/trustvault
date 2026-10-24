import { hash, verify, Options } from '@node-rs/argon2';

// OWASP Recommended parameters for Argon2id
const ARGON2_OPTIONS: Options = {
  memoryCost: 19456, // 19 MiB
  timeCost: 2,       // 2 iterations
  outputLen: 32,
  parallelism: 1,
};

export async function hashPassword(plainText: string): Promise<string> {
  if (!plainText || typeof plainText !== 'string') {
    throw new Error('Password must be a non-empty string');
  }
  return hash(plainText, ARGON2_OPTIONS);
}

export async function verifyPassword(storedHash: string, plainText: string): Promise<boolean> {
  if (!storedHash || !plainText) {
    return false;
  }
  try {
    return await verify(storedHash, plainText);
  } catch {
    return false;
  }
}
