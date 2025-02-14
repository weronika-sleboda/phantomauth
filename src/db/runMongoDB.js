import mongoose from "mongoose";
import { logger } from "../utils/logger.js";

export const runMongoDB = async (mongoUri) => {
  try {
    if(!mongoUri) {
      const message = 'MongoDB Uri not found';
      logger.error(message);
      throw new Error(message);
    }
    await mongoose.connect(mongoUri);
    logger.info('MongoDB connected');
  } catch (err) {
    logger.error(`MongoDB failed: ${err.message}`);
    throw err;
  }
}