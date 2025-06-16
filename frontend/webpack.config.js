const path = require('path');

module.exports = {
  devServer: {
    setupMiddlewares: (middlewares, devServer) => {
      // You can inject your middleware logic here if needed
      return middlewares;
    }
  }
}; 