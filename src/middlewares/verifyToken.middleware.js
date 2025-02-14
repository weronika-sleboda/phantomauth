import { User } from "../models/v1/users.model.js";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

export const verifyToken = async (req, res, next) => {
  const token = req?.cookies?.token;
  if(!token)
    return response('Missing token', 400, res);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded.userId });
    const isValid = await bcrypt.compare(token, user.token);
    if(!user || !isValid)
      return response('Invalid token', 400, res);
    req.user = decoded;
    next();
  } catch (err) {
    if(err.name === 'TokenExpiredError')
      return response('Expired token', 400, res);
    logger.error('Token verification failed');
    next(err)
  }
};