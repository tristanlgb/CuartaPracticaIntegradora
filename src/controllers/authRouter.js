const { Router } = require('express');
const { register, login, logout, getCurrentUser } = require('../controllers/authController');
const { authenticateToken } = require('../middlewares/auth');

const router = Router();

router.post('/register', register);
router.post('/login', login); // Add login route
router.post('/logout', logout);
router.get('/current', authenticateToken, getCurrentUser);

module.exports = router;
