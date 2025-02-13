import jwt from 'jsonwebtoken';

export const createJwt = (userId, email) =>  {
  const token = jwt.sign(
    { userId, email }, 
    process.env.JWT_SECRET,
    { expiresIn: `${process.env.JWT_LIFESPAN}` }
  );
  return token;
}