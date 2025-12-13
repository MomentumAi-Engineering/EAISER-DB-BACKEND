const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { OAuth2Client } = require('google-auth-library');
const crypto = require('crypto');

// Google OAuth client (verify ID tokens)
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const signToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET || 'change_this_now',
    { expiresIn: '7d' }
  );
};

exports.signup = async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) return res.status(400).json({ message: 'Missing required fields' });

  try {
    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ message: 'Email already in use' });

    const user = new User({ fullName, email, password });
    await user.save();

    return res.status(201).json({ message: 'User created' });
  } catch (err) {
    // handle common Mongoose duplicate key error (email unique)
    if (err && err.code === 11000) {
      return res.status(400).json({ message: 'Email already registered' });
    }
    // log full error for debugging
    console.error('signup error:', err && err.stack ? err.stack : err);

    // in development return the error message to client to help debugging
    return res.status(500).json({ message: (err && err.message) ? err.message : 'Server error' });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'Missing email or password' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const isMatch = await user.comparePassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

    const token = signToken(user);
    return res.json({ token, user: { id: user._id, fullName: user.fullName, email: user.email } });
  } catch (err) {
    console.error('login error:', err && err.stack ? err.stack : err);
    return res.status(500).json({ message: (err && err.message) ? err.message : 'Server error' });
  }
};

exports.me = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user });
  } catch (err) {
    console.error('me error:', err && err.stack ? err.stack : err);
    res.status(500).json({ message: (err && err.message) ? err.message : 'Server error' });
  }
};

// Google sign-in with ID token (from Google Identity Services)
exports.googleSignIn = async (req, res) => {
  const { idToken } = req.body || {};
  if (!idToken) return res.status(400).json({ message: 'Missing Google ID token' });
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.status(500).json({ message: 'Server missing GOOGLE_CLIENT_ID' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload?.email;
    const fullName = payload?.name || 'Google User';

    if (!email) return res.status(400).json({ message: 'Google account has no email' });

    let user = await User.findOne({ email });
    if (!user) {
      // create a local user with a generated password (not used directly)
      const randomPassword = crypto.randomBytes(16).toString('hex');
      user = new User({ fullName, email, password: randomPassword });
      await user.save();
    }

    const token = signToken(user);
    return res.json({ token, user: { id: user._id, fullName: user.fullName, email: user.email } });
  } catch (err) {
    console.error('googleSignIn error:', err && err.stack ? err.stack : err);
    return res.status(401).json({ message: 'Invalid Google token' });
  }
};
