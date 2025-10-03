const express = require('express');
const cors = require('cors');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const pool = require('./db');
const passport = require('./passport');
const { generateOTP, sendOTPEmail } = require('./emailService');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
// Remove trailing slash from FRONTEND_URL if present
const frontendURL = (process.env.FRONTEND_URL || 'http://localhost:3001').replace(/\/$/, '');

app.use(cors({
  origin: [frontendURL, 'http://localhost:3001'],
  credentials: true,
}));
app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// ==================== HELPER FUNCTIONS ====================

// Generate JWT token
const generateToken = (userId, email) => {
  return jwt.sign(
    { userId, email },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRY || '24h' }
  );
};

// Verify JWT token middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ==================== OTP ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Server is running' });
});

// REQUEST OTP - Send OTP to email
app.post('/api/otp/request', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email } = req.body;

  try {
    // Generate OTP
    const otp = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Save OTP to database
    await pool.query(
      'INSERT INTO otp_codes (email, code, expires_at) VALUES ($1, $2, $3)',
      [email, otp, expiresAt]
    );

    // Send OTP email
    const emailSent = await sendOTPEmail(email, otp);

    if (!emailSent) {
      return res.status(500).json({ error: 'Failed to send OTP email' });
    }

    res.json({
      message: 'OTP sent successfully',
      email,
    });
  } catch (error) {
    console.error('OTP request error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// VERIFY OTP - Verify OTP and login/register
app.post('/api/otp/verify', [
  body('email').isEmail().normalizeEmail(),
  body('code').isLength({ min: 6, max: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, code, fullName } = req.body;

  try {
    // Find valid OTP
    const otpResult = await pool.query(
      'SELECT * FROM otp_codes WHERE email = $1 AND code = $2 AND used = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1',
      [email, code]
    );

    if (otpResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid or expired OTP' });
    }

    // Mark OTP as used
    await pool.query(
      'UPDATE otp_codes SET used = TRUE WHERE id = $1',
      [otpResult.rows[0].id]
    );

    // Check if user exists
    let userResult = await pool.query(
      'SELECT * FROM users_otp WHERE email = $1',
      [email]
    );

    let user;
    if (userResult.rows.length === 0) {
      // Create new user
      const newUserResult = await pool.query(
        'INSERT INTO users_otp (email, full_name, provider, email_verified) VALUES ($1, $2, $3, $4) RETURNING *',
        [email, fullName || null, 'email', true]
      );
      user = newUserResult.rows[0];
    } else {
      user = userResult.rows[0];
      // Update email_verified if not already verified
      if (!user.email_verified) {
        await pool.query(
          'UPDATE users_otp SET email_verified = TRUE WHERE id = $1',
          [user.id]
        );
      }
    }

    // Generate JWT token
    const token = generateToken(user.id, user.email);

    // Create session
    const sessionExpiresAt = new Date(Date.now() + (parseInt(process.env.JWT_EXPIRY) || 86400) * 1000);
    await pool.query(
      'INSERT INTO sessions_otp (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, token, sessionExpiresAt]
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
      },
      token,
    });
  } catch (error) {
    console.error('OTP verify error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== SOCIAL AUTH ROUTES ====================

// Google Auth
app.get('/api/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
  passport.authenticate('google', { failureRedirect: `${process.env.FRONTEND_URL}/login?error=google_auth_failed` }),
  async (req, res) => {
    try {
      const token = generateToken(req.user.id, req.user.email);

      const sessionExpiresAt = new Date(Date.now() + (parseInt(process.env.JWT_EXPIRY) || 86400) * 1000);
      await pool.query(
        'INSERT INTO sessions_otp (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [req.user.id, token, sessionExpiresAt]
      );

      res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    } catch (error) {
      console.error('Google callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=callback_failed`);
    }
  }
);

// Facebook Auth
app.get('/api/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] })
);

app.get('/api/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: `${process.env.FRONTEND_URL}/login?error=facebook_auth_failed` }),
  async (req, res) => {
    try {
      const token = generateToken(req.user.id, req.user.email);

      const sessionExpiresAt = new Date(Date.now() + (parseInt(process.env.JWT_EXPIRY) || 86400) * 1000);
      await pool.query(
        'INSERT INTO sessions_otp (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [req.user.id, token, sessionExpiresAt]
      );

      res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    } catch (error) {
      console.error('Facebook callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=callback_failed`);
    }
  }
);

// Apple Auth
app.get('/api/auth/apple',
  passport.authenticate('apple')
);

app.post('/api/auth/apple/callback',
  passport.authenticate('apple', { failureRedirect: `${process.env.FRONTEND_URL}/login?error=apple_auth_failed` }),
  async (req, res) => {
    try {
      const token = generateToken(req.user.id, req.user.email);

      const sessionExpiresAt = new Date(Date.now() + (parseInt(process.env.JWT_EXPIRY) || 86400) * 1000);
      await pool.query(
        'INSERT INTO sessions_otp (user_id, token, expires_at) VALUES ($1, $2, $3)',
        [req.user.id, token, sessionExpiresAt]
      );

      res.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    } catch (error) {
      console.error('Apple callback error:', error);
      res.redirect(`${process.env.FRONTEND_URL}/login?error=callback_failed`);
    }
  }
);

// ==================== PROTECTED ROUTES ====================

// GET PROFILE
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, full_name, provider, avatar_url, email_verified, created_at FROM users_otp WHERE id = $1',
      [req.user.userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGOUT
app.post('/api/logout', authenticateToken, async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  try {
    await pool.query('DELETE FROM sessions_otp WHERE token = $1', [token]);
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Start server (only in local development)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`🚀 Project 2 Server running on http://localhost:${PORT}`);
  });
}

// Export for Vercel
module.exports = app;
