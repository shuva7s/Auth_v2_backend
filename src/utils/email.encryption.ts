import crypto from 'crypto';

const SECRET_KEY = Buffer.from(process.env.EMAIL_ENCRYPTION_KEY!, 'utf8');
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

export function encryptEmail(email: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, SECRET_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(email, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, encrypted]).toString('base64url');
}

export function decryptEmail(token: string): string {
  const data = Buffer.from(token, 'base64url');
  const iv = data.subarray(0, IV_LENGTH);
  const authTag = data.subarray(IV_LENGTH, IV_LENGTH + 16);
  const encryptedText = data.subarray(IV_LENGTH + 16);

  const decipher = crypto.createDecipheriv(ALGORITHM, SECRET_KEY, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(encryptedText),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}
