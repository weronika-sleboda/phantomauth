import crypto from 'crypto';

export const decrypt = (secret) => {
  const decipher = crypto.createDecipheriv(
    process.env.CRYPTO_METHOD,
    Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
    Buffer.from(process.env.ENCRYPTION_IV, 'hex')
  );
  let decrypted = decipher.update(secret, 'hex', 'utf8');
  decrypted +=  decipher.final('utf8');
  return decrypted;
}