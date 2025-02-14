import { User } from '../../models/v1/users.model.js';
import bcrypt from 'bcrypt';
import { validateEmail } from '../../utils/validateEmail.js';
import { validatePass } from '../../utils/validatePass.js';
import { createJwt } from '../../utils/createJwt.js';
import { logger } from '../../utils/logger.js';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';
import { response } from '../../utils/response.js';
import jwt from 'jsonwebtoken';
import { encrypt } from '../../utils/encrypt.js';

export const register = async (req, res, next) => {
  const { email, password, bottrap } = req.body;
  if(!email || !password)
    return response('Missing fields', 400, res);
  if(bottrap) 
    return response('Bot detected', 400, res);
  try {
    const userExists = await User.findOne({ email });
    if(userExists) {
      return response('User already exists', 400, res);
    }
    validateEmail(email);
    validatePass(password);
    const hashPass = await bcrypt.hash(
      password, 12);
    const newUser = new User({ 
      email, 
      password: hashPass,
    });
    await newUser.save();
    return response('User registration succeeded', 201, res, true);
  } catch (err) {
    logger.error('User registration failed');
    next(err);
  }
};

export const login = async (req, res, next) => {
  const { email, password } = req.body;
  if(!email || !password)
    return response('Missing fields', 400, res);
  try {
    const user = await User.findOne({ email });
    if(!user) 
      return response('Authentication failed', 400, res);
    const isMatch = await bcrypt.compare(
      password, user.password);
    if(!isMatch) 
      return response('Authentication failed', 400, res);
    const token = createJwt(user._id, email);
    const hashToken = await bcrypt.hash(token, 12);
    user.token = hashToken;
    await user.save();
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV !== 'development',
      sameSite: 'Strict',
      maxAge: 3600000
    });
    return response('User login succeeded', 200, res, true);
  } catch (err) {
    logger.error('User login failed');
    next(err);
  }
};

export const logout = async (req, res, next) => {
  const token = req?.cookies?.token;
  if(!token)
    return response('Missing token', 400, res);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded.userId});
    if(!user) return response('Invalid token', 400, res);
    user.token = null;
    await user.save();
    res.clearCookie('token');
    return response('User logout succeeded', 200, res, true);
  } catch (err) {
    logger.error('User logout failed');
    next(err);
  }
};

export const enable2FA = async (req, res, next) => {
  const { email } = req.body;
  if(!email)
    return response('Missing fields', 400, res);
  try {
    const user = await User.findOne({ email });
    if(!user)
      return response('User not found', 404, res);
    const secret = speakeasy.generateSecret({ 
      name: `PhantomGate Auth: ${email}`}
    );
    const encrypted = encrypt(secret.base32);
    user.twoFAsecret = encrypted;
    user.twoFAEnabled = true;
    await user.save();
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);
    return response(qrCode, 200, res, true);
  } catch (err) {
    logger.error('Enabling 2FA failed');
    next(err);
  }
};

export const resetPassword = async (req, res, next) => {
  const { email, newPass, confirmPass } = req.body;
  if(!email || !newPass || !confirmPass)
    return response('Missing fields', 400, res);
  if(newPass !== confirmPass)
    return response('Passwords don\'t match', 400, res);
  try {
    const user = await User.findOne({ email });
    if(!user) 
      return response('User not found', 400, res);
    validatePass(newPass);
    const hashPass = await bcrypt.hash(newPass, 10);
    user.password = hashPass;
    user.token = null;
    await user.save();
    return response('Passwords reset succeeded', 200, res, true);
  } catch (err) {
    logger.error('Password reset failed');
    next(err);
  }
};




