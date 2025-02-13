import { logger } from "./logger.js";

export const response = (message, code, res, isSuccess = false) => {
  logger[isSuccess?  'info' : 'error'](message);
  return res.status(code).json({
    success: isSuccess,
    message: message
  });
};