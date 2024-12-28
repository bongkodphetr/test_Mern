const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const { 
  register,
  login,
  getMe
} = require('../controllers/authController');

// @route   POST api/auth/register
// @desc    Register user
// @access  Public
router.post('/register', register);

// @route   POST api/auth/login
// @desc    Login user
// @access  Public
router.post('/login', login);

// @route   GET api/auth/me
// @desc    Get user data
// @access  Private
router.get('/me', auth, getMe);

module.exports = router; 