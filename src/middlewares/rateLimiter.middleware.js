import { logger } from "../utils/logger.js";

export const rateLimiter = (limiter) => {
  return async (req, res, next) => {
    try {
      await limiter.consume(req.ip, 1);
      next();
    } catch (err) {
      logger.warn(`Exceeded rate limits for IP: ${req.ip}`);
      const error = new Error('Too many requests, try again later');
      error.statusCode = 429;
      next(error);
    }
  }
}