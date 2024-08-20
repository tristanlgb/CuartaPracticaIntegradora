const { hashPassword, comparePassword } = require('../utils/hash');
const userDao = require('../daos/userDao');
const jwt = require('jsonwebtoken');
const { sendMail } = require('../utils/mailer');
const UserDto = require('../dtos/userDto');
const crypto = require('crypto');
const User = require('../models/User');

// Register a new user
const register = async (req, res) => {
  const { first_name, last_name, email, password } = req.body;

  try {
    const existingUser = await userDao.findUserByEmail(email);
    if (existingUser) {
      return res.status(400).json({ message: 'Email already taken' });
    }

    const hashedPassword = await hashPassword(password);
    const newUser = await userDao.createUser({ first_name, last_name, email, password: hashedPassword });

    sendMail(email, 'Welcome', 'Thank you for registering');

    return res.status(201).json({ message: 'User created', user: new UserDto(newUser) });
  } catch (err) {
    res.status(500).json({ message: 'Error creating user', error: err.message });
  }
};

// Login a user and update the last connection
const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await userDao.findUserByEmail(email);
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const isValid = await comparePassword(password, user.password);
    if (!isValid) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_PRIVATE_KEY, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true });

    user.last_connection = new Date();
    await user.save();

    res.status(200).json({ message: 'Logged in successfully', token });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
};

// Logout a user and update the last connection
const logout = async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(400).json({ message: 'Not logged in' });
    }

    const decoded = jwt.verify(token, process.env.JWT_PRIVATE_KEY);
    const user = await userDao.findById(decoded.id);
    if (user) {
      user.last_connection = new Date();
      await user.save();
    }

    res.clearCookie('token');
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error logging out', error: err.message });
  }
};

// Get the currently authenticated user
const getCurrentUser = async (req, res) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: 'Not authenticated' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_PRIVATE_KEY);
    const user = await userDao.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    const userDto = new UserDto(user);
    res.status(200).json({ user: userDto });
  } catch (err) {
    res.status(401).json({ message: 'Invalid token', error: err.message });
  }
};

// Request a password reset
const requestPasswordReset = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await userDao.findUserByEmail(email);
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const token = crypto.randomBytes(20).toString('hex');
    const resetPasswordExpires = Date.now() + 3600000; // 1 hour

    user.resetPasswordToken = token;
    user.resetPasswordExpires = resetPasswordExpires;
    await user.save();

    const resetUrl = `http://localhost:8080/reset-password/${token}`;

    sendMail(user.email, 'Password Reset', `Click here to reset your password: ${resetUrl}`);

    res.status(200).json({ message: 'Password reset link sent' });
  } catch (err) {
    res.status(500).json({ message: 'Error requesting password reset', error: err.message });
  }
};

// Reset the user's password
const resetPassword = async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  try {
    const user = await userDao.findUserByResetToken(token);
    if (!user || user.resetPasswordExpires < Date.now()) {
      return res.status(400).json({ message: 'Password reset token is invalid or has expired' });
    }

    if (await comparePassword(password, user.password)) {
      return res.status(400).json({ message: 'Cannot use the same password' });
    }

    user.password = await hashPassword(password);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.status(200).json({ message: 'Password has been reset' });
  } catch (err) {
    res.status(500).json({ message: 'Error resetting password', error: err.message });
  }
};

module.exports = { register, login, logout, getCurrentUser, requestPasswordReset, resetPassword };
