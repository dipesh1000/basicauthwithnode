const asyncHandler = require('express-async-handler');
const User = require('../model/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Token = require('../model/tokenModel');
const sendEmail = require('../utils/sendEmail');
const { Error } = require('mongoose');
global.crypto = require('crypto');

const generatedToken = (id) => {
  return jwt.sign(
    {
      id,
    },
    process.env.SECRET,
    { expiresIn: '1h' }
  );
};

//@desc Register User
//@route POST/api/register
//@access Public
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password } = req.body;

  //validation
  if (!name || !email || !password) {
    res.status(400);
    throw new Error('Enter all the field');
  }

  if (password.length < 6) {
    res.status(400);
    throw new Error('Password must contain 6 character');
  }

  //check if the user exists
  const userExist = await User.findOne({ email });

  if (userExist) {
    res.status(400);
    throw new Error('Email has already used');
  }

  // create user
  const user = await User.create({
    name,
    email,
    password,
  });

  //Generate a token
  const token = await generatedToken(user._id);

  //Send Http-only cookie
  await res.cookie('token', token, {
    path: '/',
    httpOnly: true,
    expires: new Date(Date.now() + 1000 * 86400), // 1 Day
    // sameSite: 'none',
    // secure: true,
  });

  if (user) {
    res.status(201).json({
      message: 'Successful',
      data: user,
      token,
    });
  } else {
    res.status(400);
    throw new Error('Invalid User data');
  }
});

//@desc Login User
//@route POST/api/login
//@access Public
const userLogin = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400);
    throw new Error('Please enter email or password');
  }

  //check if the user exist
  const userExist = await User.findOne({ email });

  if (!userExist) {
    res.status(400);
    throw new Error('User Not exist');
  }

  const passswordisCorrect = await bcrypt.compare(password, userExist.password);

  if (userExist && passswordisCorrect) {
    //Generate a token
    const token = await generatedToken(userExist._id);

    //Send Http-only cookie
    await res.cookie('token', token, {
      path: '/',
      httpOnly: true,
      expires: new Date(Date.now() + 1000 * 86400), // 1 Day
      // sameSite: 'none',
      // secure: true,
    });
    res.status(200);
    res.json({
      message: 'Logged in Success',
      data: { user: userExist, token },
    });
  } else {
    res.status(400);
    throw new Error('Invalid User and password');
  }
});

//@desc Logut User
//@route GET/api/logout
//@access Private
const userLogout = asyncHandler(async (req, res) => {
  //Send Http-only cookie
  await res.cookie('token', '', {
    path: '/',
    httpOnly: true,
    expires: new Date(0), // 1 Day
    // sameSite: 'none',
    // secure: true,
  });
  return res.status(200).json({ message: 'Logout success' });
});

//@desc Logut User
//@route GET/api/logout
//@access Private
const getUser = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id).select('-password');

  if (user) {
    res.status(200);
    res.json({
      message: 'Fetch Success',
      data: user,
    });
  } else {
    res.status(400);
    throw new Error('User not found');
  }
});

//@desc Auth Status
//@route GET/api/authStatus
//@access Private
const authStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  //verify Token
  const varified = jwt.verify(token, process.env.SECRET);
  if (varified) {
    return res.json(true);
  }
  return res.json(false);
});

//@desc User Update
//@route PATCH/api/user/update
//@access Private
const userUpdate = asyncHandler(async (req, res) => {
  console.log(req.user._id, 'from line no 167');
  const user = await User.findById(req.user._id);
  if (user) {
    const { name, email, photo, phone, bio } = user;
    (user.email = email),
      (user.name = req.body.name || name),
      (user.photo = req.body.photo || photo),
      (user.phone = req.body.phone || phone),
      (user.bio = req.body.bio || bio);
    user.isAdmin = req.body.isAdmin || isAdmin;

    const updatedUser = await user.save();
    res.status(201).json({
      message: 'update success',
      data: updatedUser,
    });
  } else {
    res.status(404);
    throw new Error('User Not Found!');
  }
});

const changePassword = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);
  console.log(user, 'From user');
  if (user) {
    const { password } = user;
    const passswordisCorrect = await bcrypt.compare(
      req.body.oldPassword,
      password
    );
    console.log(passswordisCorrect, 'From password is correct');
    if (passswordisCorrect) {
      user.password = req.body.password || password;
      await user.save();
      res.status(200);
      res.json({
        message: 'Reset Successfull',
      });
    } else {
      res.status(400);
      throw new Error('Old Password Not Match');
    }
  } else {
    res.status(404);
    throw new Error('User Not Found');
  }
});

const forgetPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (user) {
    // Delete if the token exist
    const tokenExist = await Token.findOne({ userId: user._id });

    if (tokenExist) {
      await tokenExist.deleteOne();
    }

    // Reset Token
    let resetToken = crypto.randomBytes(32).toString('hex') + user._id;

    //Hash token before saving to db
    const hashToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    //Save token to Db
    await new Token({
      userId: user._id,
      token: hashToken,
      createdAt: Date.now(),
      expiresAt: Date.now() + 30 * (60 * 1000),
    }).save();

    //Construct Reset URL
    const resetURL = `${process.env.HOME_URL}/reset-password/${resetToken}`;

    //Reset Email
    const message = `
    <h2>hello ${user.name}</h2>
    <p>Please use the url below</p>
    <p>This link is valid for 30 minutes</p>
    <a href=${resetURL} clicktracking=off>${resetURL}</a>
    <p>Best Regards</p>
    `;
    const subject = 'Password Reset Request';
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;

    try {
      await sendEmail(subject, message, send_to, sent_from);
      res.status(200);
      res.json({ success: true, message: 'Reset Email Send' });
    } catch (error) {
      res.status(500);
      throw new Error('Email Not Send try again');
    }
  } else {
    res.status(404);
    throw new Error('User not found');
  }
});

const resetPassword = asyncHandler(async (req, res) => {
  const { password } = req.body;
  const { resetToken } = req.params;
  //Hash token before saving to db
  const hashToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  //find token in DB
  const userToken = await Token.findOne({
    token: hashToken,
    expiresAt: { $gt: Date.now() },
  });
  if (!userToken) {
    res.status(404);
    throw new Error('token not found');
  }

  //Find User
  const user = await User.findById({ _id: userToken.userId });
  user.password = password;
  await user.save();
  res.status(200).json({
    message: 'Password reset successful, Please Login',
  });
});

//@desc Access By Admin Only
//@route GET/api/user
//@access Private [Access Only By Admin]
const getAllUser = asyncHandler(async (req, res) => {
  const users = await User.find({});
  res.status(201).json({
    message: 'Fetch successful',
    data: users,
  });
});

module.exports = {
  registerUser,
  userLogin,
  userLogout,
  getUser,
  userUpdate,
  authStatus,
  resetPassword,
  changePassword,
  forgetPassword,
  getAllUser,
};
