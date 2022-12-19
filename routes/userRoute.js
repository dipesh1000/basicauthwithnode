const express = require('express');
const router = express.Router();
const {
  registerUser,
  userLogin,
  userLogout,
  getUser,
  authStatus,
  userUpdate,
  resetPassword,
  forgetPassword,
  changePassword,
  getAllUser,
} = require('../controller/userController');
const {
  accessProtect,
  adminProtectedRoute,
} = require('../middleware/authMiddleware');

router.post('/register', registerUser);
router.post('/login', userLogin);
router.get('/logout', userLogout);
router.get('/getUser', accessProtect, getUser);
router.get('/authStatus', authStatus);
router.patch('/user-update', accessProtect, userUpdate);
router.patch('/change-password', accessProtect, changePassword);
router.post('/forgot-password', forgetPassword);
router.put('/reset-password/:resetToken', resetPassword);

router.get('/', accessProtect, adminProtectedRoute, getAllUser);

module.exports = router;
