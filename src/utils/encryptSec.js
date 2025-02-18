import base32 from 'base32';
import crypto from 'crypto';

export const encryptSec = (b32secret) => {
  try {
    const secBuffer = Buffer.from(base32.decode(b32secret), 'binary');
    const cipher = crypto.createCipheriv(
      process.env.CRYPTO_METHOD,
      Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
      Buffer.from(process.env.ENCRYPTION_IV, 'hex')
    );
    let encrypted = cipher.update(secBuffer, 'binary', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (err) {
    throw new Error(`Encryption failed: ${err.message}`);
  }
}