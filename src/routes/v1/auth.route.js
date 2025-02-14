import express from 'express';
import { 
  login,
  register,
  logout,
  resetPassword,
  enable2FA,
} from '../../controllers/v1/auth.controller.js';
import { rateLimiter } from '../../middlewares/rateLimiter.middleware.js';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { createLimiter } from '../../utils/createLimiter.js';

const router = express.Router();

router.post('/register', rateLimiter(
  createLimiter({
    points: 3,
    duration: 10 * 60
  }, RateLimiterMemory)), 
  register
);

router.post('/login', rateLimiter(
  createLimiter({
    points: 5,
    duration: 60,
    blockDuration: 15 * 60
  }, RateLimiterMemory)), 
  login
);

router.post('/logout', rateLimiter(
  createLimiter({
    points: 10,
    duration: 60,
    }, RateLimiterMemory)), 
  logout
);

router.post('/enable-2FA', rateLimiter(
  createLimiter({
    points: 3,
    duration: 60 * 60
  }, RateLimiterMemory)), 
  enable2FA
);

router.post('/reset-password', rateLimiter(
  createLimiter({
    points: 5,
    duration: 15 * 60,
  }, RateLimiterMemory)), 
  resetPassword
);

export { router as authRouter };