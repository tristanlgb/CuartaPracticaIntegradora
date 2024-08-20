const express = require('express');
const router = express.Router();
const passport = require('passport');
const {
  register,
  login,
  logout,
  getCurrentUser,
  requestPasswordReset,
  resetPassword,
} = require('../controllers/authController');
const { authenticateToken } = require('../middlewares/auth');

// Registration and Login routes
router.post('/register', register);
router.post('/login', passport.authenticate('local'), login);
router.post('/logout', logout);

// GitHub OAuth routes
router.get('/github', passport.authenticate('github', { scope: ['user:email'] }));
router.get('/github/callback', 
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/');
  }
);

// Other routes
router.get('/current', authenticateToken, getCurrentUser);
router.post('/request-password-reset', requestPasswordReset);
router.post('/reset-password/:token', resetPassword);

module.exports = router;
