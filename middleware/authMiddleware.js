const asyncHandler = require('express-async-handler');
const jwt = require('jsonwebtoken');
const User = require('../model/userModel');

const accessProtect = asyncHandler(async (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      res.status(400);
      throw new Error('Not Authorise please login');
    }

    //verify token
    const verified = jwt.verify(token, process.env.SECRET);

    //get userId from token
    const user = await User.findById(verified.id).select('-password');
    if (!user) {
      res.status(400);
      throw new Error('User Not Foound');
    }
    req.user = user;
    next();
  } catch (error) {
    res.status(400);
    throw new Error('Not Authorise please login');
  }
});

const adminProtectedRoute = asyncHandler(async (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    next();
  } else {
    res.status(401);
    throw new Error('UnAuthrise Error');
  }
});

module.exports = { accessProtect, adminProtectedRoute };
