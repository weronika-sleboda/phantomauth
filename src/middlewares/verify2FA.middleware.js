import { User } from '../models/v1/users.model.js';
import { decryptSec } from '../utils/decryptSec.js';
import speakeasy from 'speakeasy';
import { response } from '../utils/response.js';

export const verify2FA = async (req, res, next) => {
  const { email, otp } = req.body;
  if(!email || !otp)
    return response('Missing fields', 400, res);
  try {
    const user = await User.findOne({ email });
    if(!user) 
      return response('Invalid credentials', 400, res);
    const decrypted = decryptSec(user.twoFAsecret);
    const verified = speakeasy.totp.verify({
      secret: decrypted,
      encoding: 'base32',
      token: otp,
      window: 1
    });
    if(!verified)
      return response('Verification failed', 400, res);
    req.userId = user._id;
    next();
  } catch (err) {
    return response(`2FA Verification failed: ${err.message}`, 400, res);
  }
};