import crypto from 'crypto';
import base32 from 'base32';

export const decryptSec = (encryptedSec) => {
  try {
    const decipher = crypto.createDecipheriv(
      process.env.CRYPTO_METHOD,
      Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
      Buffer.from(process.env.ENCRYPTION_IV, 'hex')
    );
    let decrypted = decipher.update(encryptedSec, 'hex', 'binary');
    decrypted +=  decipher.final('binary');
    return base32.encode(decrypted);
  } catch (err) {
    throw new Error(`Decryption failed: ${err.message}`);
  }
}