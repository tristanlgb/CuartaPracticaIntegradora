const logger = require('../config/logger');

const requestLogger = (req, res, next) => {
  logger.info(`Request: ${req.method} ${req.url}`);
  next();
};

const errorLogger = (err, req, res, next) => {
  logger.error(`Error: ${err.message}`);
  next(err);
};

module.exports = { requestLogger, errorLogger };
