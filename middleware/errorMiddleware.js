const errorHandler = (err, req, res, next) => {
  console.log(res.statusCode, err, 'From status code');
  const statusCode = res.statusCode ? res.statusCode : 500;
  res.status(statusCode);

  //error stack means local of the error
  res.json({
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : null,
  });
};

module.exports = errorHandler;
