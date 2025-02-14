import { User } from '../models/v1/users.model.js';
import { decrypt } from 'dotenv';
import speakeasy from 'speakeasy';

export const verify2FA = async (req, res, next) => {
  const { email, otp } = req.body;
  if(!email || !otp)
    return response('Missing fields', 400, res);
  try {
    const user = await User.findOne({ email });
    if(!user) 
      return response('Invalid credentials', 400, res);
    const decrypted = decrypt(user.twoFAsecret);
    const verified = speakeasy.totp.verify({
      secret: decrypted,
      encoding: 'base32',
      token: otp,
      window: 1
    });
    if(!verified)
      return response('Verification failed', 400, res);
    next();
  } catch (err) {
    logger.error('2FA Verification failed');
    next(err);
  }
};