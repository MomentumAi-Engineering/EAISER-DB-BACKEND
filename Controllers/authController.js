const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const signToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
};

/**
 * SIGNUP
 */
exports.signup = async (req, res) => {
  try {
    console.log("👉 SIGNUP REQUEST BODY:", req.body); // DEBUG LOG

    // Robustness: Accept 'fullName' (preferred) or 'name' (legacy/fallback)
    const fullName = req.body.fullName || req.body.name;
    const { password } = req.body;
    let { email } = req.body;

    if (!fullName || !email || !password) {
      console.log("❌ Missing fields:", { fullName, email: !!email, pw: !!password });
      return res.status(400).json({
        message: 'Missing required fields',
        received: req.body,
        details: {
          hasFullName: !!fullName,
          hasEmail: !!email,
          hasPassword: !!password
        }
      });
    }

    email = email.toLowerCase(); // Normalize email

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ message: 'Email already registered' });
    }

    const user = new User({ fullName, email, password });
    await user.save();

    return res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    console.error('signup error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

/**
 * LOGIN
 */
exports.login = async (req, res) => {
  try {
    const { password } = req.body;
    let { email } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Missing email or password' });
    }

    email = email.toLowerCase(); // Normalize email

    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = signToken(user);
    return res.json({
      token,
      user: { id: user._id, fullName: user.fullName, email: user.email },
    });
  } catch (err) {
    console.error('login error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
};

/**
 * ME
 */
exports.me = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error('me error:', err);
    res.status(500).json({ message: 'Server error' });
  }
};

/**
 * GOOGLE SIGN-IN
 */
exports.googleSignIn = async (req, res) => {
  try {
    const { idToken } = req.body;
    if (!idToken) {
      return res.status(400).json({ message: 'Missing Google ID token' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const fullName = payload.name || 'Google User';

    if (!email) {
      return res.status(400).json({ message: 'Google account has no email' });
    }

    let user = await User.findOne({ email });

    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString('hex');
      user = new User({ fullName, email, password: randomPassword });
      await user.save();
    }

    const token = signToken(user);

    return res.json({
      token,
      user: { id: user._id, fullName: user.fullName, email: user.email },
    });
  } catch (err) {
    console.error('googleSignIn error:', err);
    return res.status(401).json({ message: 'Invalid Google token' });
  }
};
