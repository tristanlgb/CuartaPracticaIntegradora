const User = require('../models/users');

const findUserByUsername = async (username) => {
  return await User.findOne({ username });
};

const findByGithubId = async (githubId) => {
  return await User.findOne({ githubId });
};

const createUser = async (userData) => {
  const user = new User(userData);
  return await user.save();
};

const findById = async (id) => {
  return await User.findById(id);
};

module.exports = {
  findUserByUsername,
  findByGithubId,
  createUser,
  findById
};