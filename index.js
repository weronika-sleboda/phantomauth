import express from 'express';
import dotenv from 'dotenv';
import { authRouter } from './src/routes/v1/auth.route.js';
import { logger } from './src/utils/logger.js';
import { runMongoDB } from './src/db/runMongoDB.js';
import { errorHandler } from './src/middlewares/errorHandler.middleware.js';
import helmet from 'helmet';

dotenv.config();

const PORT = process.env.PORT || 5000;
const BASE_URL = process.env.BASE_URL;
const API_URL = process.env.API_URL;

const startServer = async () => {
  try {
    await runMongoDB();
    const app = express();
    app.use(helmet());
    app.use(express.json());
    app.use(`${API_URL}/auth`, authRouter);
    app.use(errorHandler);
    app.listen(PORT, () => {
      logger.info(`PhantomAuth runs at ${BASE_URL}`);
    });
  } catch (err) {
    logger.error(`Phantom Auth stopped: ${err.message}`);
    process.exit(1);
  }
}

startServer();