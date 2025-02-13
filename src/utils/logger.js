import winston from "winston";

const { format, transports, createLogger } = winston;

const logFormat = format.combine(
  format.colorize({ level: true }),
  format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss'}),
  format.printf(({ timestamp, level, message }) => {
    return `${timestamp} [${level}] ${message}`
  })
);

export const logger = createLogger({
  level: "info",
  format: logFormat,
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'app.log' })
  ]
});