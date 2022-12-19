const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
    },
    email: {
      type: String,
      required: [true, 'Email is Required'],
    },
    password: {
      type: String,
      required: [true, 'password is Required'],
      minLenght: [6, 'shound be minimum 6 character'],
    },
    photo: {
      type: String,
      required: [true, 'Photo is Required'],
      default: 'https://dummyimage.com/200x200/ddd/fff',
    },
    phone: {
      type: String,
      default: '+977',
      required: [true, 'Phone is Required'],
    },
    bio: {
      type: String,
      minLenght: [6, 'shound be minimum 6 character'],
    },
    isAdmin: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

//Encrypt password before saving to DB
userSchema.pre('save', async function (next) {
  // every time password not hashed
  if (!this.isModified('password')) {
    return next();
  }
  //bcrypt password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(this.password, salt);
  this.password = hashedPassword;
  next();
});

const User = mongoose.model('User', userSchema);
module.exports = User;
