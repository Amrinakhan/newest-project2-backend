const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const AppleStrategy = require('passport-apple').Strategy;
const pool = require('./db');
require('dotenv').config();

// Serialize user
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user
passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users_otp WHERE id = $1', [id]);
    done(null, result.rows[0]);
  } catch (error) {
    done(error, null);
  }
});

// Google Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          // Check if user exists
          const existingUser = await pool.query(
            'SELECT * FROM users_otp WHERE provider = $1 AND provider_id = $2',
            ['google', profile.id]
          );

          if (existingUser.rows.length > 0) {
            return done(null, existingUser.rows[0]);
          }

          // Check if email already exists with different provider
          const emailCheck = await pool.query(
            'SELECT * FROM users_otp WHERE email = $1',
            [profile.emails[0].value]
          );

          if (emailCheck.rows.length > 0) {
            // Link Google account to existing user
            const userId = emailCheck.rows[0].id;
            await pool.query(
              'INSERT INTO social_accounts (user_id, provider, provider_id, access_token) VALUES ($1, $2, $3, $4)',
              [userId, 'google', profile.id, accessToken]
            );
            return done(null, emailCheck.rows[0]);
          }

          // Create new user
          const newUser = await pool.query(
            'INSERT INTO users_otp (email, full_name, provider, provider_id, avatar_url, email_verified) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [
              profile.emails[0].value,
              profile.displayName,
              'google',
              profile.id,
              profile.photos[0]?.value,
              true,
            ]
          );

          // Create social account entry
          await pool.query(
            'INSERT INTO social_accounts (user_id, provider, provider_id, access_token) VALUES ($1, $2, $3, $4)',
            [newUser.rows[0].id, 'google', profile.id, accessToken]
          );

          done(null, newUser.rows[0]);
        } catch (error) {
          done(error, null);
        }
      }
    )
  );
}

// Facebook Strategy
if (process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET) {
  passport.use(
    new FacebookStrategy(
      {
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: process.env.FACEBOOK_CALLBACK_URL,
        profileFields: ['id', 'emails', 'name', 'picture.type(large)'],
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          // Check if user exists
          const existingUser = await pool.query(
            'SELECT * FROM users_otp WHERE provider = $1 AND provider_id = $2',
            ['facebook', profile.id]
          );

          if (existingUser.rows.length > 0) {
            return done(null, existingUser.rows[0]);
          }

          // Check if email already exists
          const email = profile.emails?.[0]?.value;
          if (email) {
            const emailCheck = await pool.query(
              'SELECT * FROM users_otp WHERE email = $1',
              [email]
            );

            if (emailCheck.rows.length > 0) {
              const userId = emailCheck.rows[0].id;
              await pool.query(
                'INSERT INTO social_accounts (user_id, provider, provider_id, access_token) VALUES ($1, $2, $3, $4)',
                [userId, 'facebook', profile.id, accessToken]
              );
              return done(null, emailCheck.rows[0]);
            }
          }

          // Create new user
          const fullName = `${profile.name.givenName} ${profile.name.familyName}`;
          const newUser = await pool.query(
            'INSERT INTO users_otp (email, full_name, provider, provider_id, avatar_url, email_verified) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [
              email || `facebook_${profile.id}@placeholder.com`,
              fullName,
              'facebook',
              profile.id,
              profile.photos[0]?.value,
              !!email,
            ]
          );

          await pool.query(
            'INSERT INTO social_accounts (user_id, provider, provider_id, access_token) VALUES ($1, $2, $3, $4)',
            [newUser.rows[0].id, 'facebook', profile.id, accessToken]
          );

          done(null, newUser.rows[0]);
        } catch (error) {
          done(error, null);
        }
      }
    )
  );
}

// Apple Strategy
if (process.env.APPLE_CLIENT_ID && process.env.APPLE_TEAM_ID) {
  passport.use(
    new AppleStrategy(
      {
        clientID: process.env.APPLE_CLIENT_ID,
        teamID: process.env.APPLE_TEAM_ID,
        keyID: process.env.APPLE_KEY_ID,
        privateKeyLocation: process.env.APPLE_PRIVATE_KEY_PATH,
        callbackURL: process.env.APPLE_CALLBACK_URL,
        passReqToCallback: true,
      },
      async (req, accessToken, refreshToken, idToken, profile, done) => {
        try {
          const appleId = profile.id;
          const email = profile.email;

          // Check if user exists
          const existingUser = await pool.query(
            'SELECT * FROM users_otp WHERE provider = $1 AND provider_id = $2',
            ['apple', appleId]
          );

          if (existingUser.rows.length > 0) {
            return done(null, existingUser.rows[0]);
          }

          // Check if email already exists
          if (email) {
            const emailCheck = await pool.query(
              'SELECT * FROM users_otp WHERE email = $1',
              [email]
            );

            if (emailCheck.rows.length > 0) {
              const userId = emailCheck.rows[0].id;
              await pool.query(
                'INSERT INTO social_accounts (user_id, provider, provider_id, access_token) VALUES ($1, $2, $3, $4)',
                [userId, 'apple', appleId, accessToken]
              );
              return done(null, emailCheck.rows[0]);
            }
          }

          // Create new user
          const fullName = profile.name
            ? `${profile.name.firstName} ${profile.name.lastName}`
            : 'Apple User';

          const newUser = await pool.query(
            'INSERT INTO users_otp (email, full_name, provider, provider_id, email_verified) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [
              email || `apple_${appleId}@placeholder.com`,
              fullName,
              'apple',
              appleId,
              !!email,
            ]
          );

          await pool.query(
            'INSERT INTO social_accounts (user_id, provider, provider_id, access_token) VALUES ($1, $2, $3, $4)',
            [newUser.rows[0].id, 'apple', appleId, accessToken]
          );

          done(null, newUser.rows[0]);
        } catch (error) {
          done(error, null);
        }
      }
    )
  );
}

module.exports = passport;
