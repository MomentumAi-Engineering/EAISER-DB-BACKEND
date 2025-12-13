const express = require('express');
const router = express.Router();
const authController = require('../Controllers/authController');
const authMiddleware = require('../middleware/authMiddleware');

router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/google', authController.googleSignIn);
router.get('/me', authMiddleware, authController.me);

module.exports = router;
