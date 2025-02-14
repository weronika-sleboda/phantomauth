import express from 'express';
import { authRouter } from '../routes/v1/auth.route.js';
import { logger } from '../utils/logger.js';
import { runMongoDB } from '../db/runMongoDB.js';
import { errorHandler } from '../middlewares/errorHandler.middleware.js';
import helmet from 'helmet';
import { verifyToken } from '../middlewares/verifyToken.middleware.js';
import { verify2FA } from '../middlewares/verify2FA.middleware.js';

export const phantomauth = async (mongoUri, apiUrl) => {
  try {
    logger.info('PhantomAuth running');
    await runMongoDB(mongoUri);
    const app = express();
    app.use(helmet());
    app.use(express.json());
    app.use(`${apiUrl}`, authRouter);
    app.use(errorHandler);
    return { app, verifyToken, verify2FA }
  } catch (err) {
    logger.error(`Phantom Auth stopped: ${err.message}`);
    process.exit(1);
  }
};