class AppError extends Error {
    constructor(message, statusCode) {
      super(message);
      this.statusCode = statusCode;
      this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
      this.isOperational = true;
      Error.captureStackTrace(this, this.constructor);
    }
  }
  
  const errorHandler = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';
  
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  };
  
  const errorDictionary = {
    POKEMON_CREATION_ERROR: new AppError('Failed to create Pokemon', 400),
    CART_ADD_ERROR: new AppError('Failed to add to cart', 400),
    USER_NOT_FOUND: new AppError('User not found', 404),
    PRODUCT_NOT_FOUND: new AppError('Product not found', 404),
  };
  
  module.exports = { AppError, errorHandler, errorDictionary };