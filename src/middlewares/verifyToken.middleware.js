import { User } from "../models/v1/users.model.js";
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { response } from "../utils/response.js";

export const verifyToken = async (req, res, next) => {
  const token = req?.cookies?.token;
  if(!token)
    return response('Missing token', 400, res);
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ _id: decoded.userId });
    if (!user) 
      return response('Invalid token', 400, res);
    const isValid = process.env.NODE_ENV === 'test' 
      ? token === user.token
      : await bcrypt.compare(token, user.token);
    if (!isValid) 
      return response('Invalid token', 400, res);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    if(err.name === 'TokenExpiredError')
      return response('Expired token', 400, res);
    return response('Token verification failed', 400, res);
  }
};