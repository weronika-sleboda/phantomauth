import { logger } from '../utils/logger.js';

export const errorHandler = async (err, req, res, next) => {
  logger.error(err.message);
  return res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || 'Unexpected error occured'
  });
};