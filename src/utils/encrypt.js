import crypto from 'crypto';

export const encrypt = (secret) => {
  const cipher = crypto.createCipheriv(
    process.env.CRYPTO_METHOD,
    Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
    Buffer.from(process.env.ENCRYPTION_IV, 'hex')
  );
  let encrypted = cipher.update(secret, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}