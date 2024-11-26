const express = require('express');
const authRoutes = require('./routes/authRoutes');
const productRoutes = require('./routes/productRoutes');
const categoryRoutes = require('./routes/categoryRoutes');
const orderRoutes = require('./routes/orderRoutes');
const addressRoutes = require('./routes/addressRoutes');
const brandRoutes = require('./routes/brandRoutes');
const cartRoutes = require('./routes/cartRoutes');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors');
const dotenv = require('dotenv');
const User = require('./models/User');
dotenv.config();

const app = express();

// JWT Token Generation
const jwt = require('jsonwebtoken');
const createToken = (id) => {
    return jwt.sign({ id }, '23456323456@34654456', { expiresIn: '1h' });
};

// Check Required Environment Variables
const requiredEnvVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_CALLBACK_URL', 'DATABASE_URI'];
const missingEnvVars = requiredEnvVars.filter((varName) => !process.env[varName]);

if (missingEnvVars.length > 0) {
    console.log(`\n[ERROR] Missing environment variables: ${missingEnvVars.join(', ')}\n`);
    process.exit(1);
}

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL || '*',
     methods: ['GET', 'POST', 'PUT', 'DELETE'],
      credentials: true }));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'default_secret',
        resave: false,
        saveUninitialized: true,
    })
);
app.use(passport.initialize());
app.use(passport.session());

// Google OAuth Strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL,
        },
        async (accessToken, refreshToken, profile, done) => {
            try {
                let user = await User.findOne({ email: profile._json.email });
                if (!user) {
                    user = await User.create({
                        username: profile._json.given_name,
                        email: profile._json.email,
                        role: 'user',
                        image: profile._json.picture,
                        authProvider: 'google',
                        authProviderId: profile._json.sub,
                    });
                }
                const token = createToken(user._id);
                return done(null, { user, token });
            } catch (error) {
                return done(error, null);
            }
        }
    )
);

passport.serializeUser((user, done) => {
    done(null, user);
});
passport.deserializeUser((user, done) => {
    done(null, user);
});

// Database Connection
mongoose
    .connect(process.env.DATABASE_URI)
    .then(() => console.log('Connected to DB'))
    .catch((err) => console.log(err));

// Routes
app.use(authRoutes);
app.use( productRoutes);
app.use(categoryRoutes);
app.use(cartRoutes);
app.use(orderRoutes);
app.use(addressRoutes);
app.use(brandRoutes);

module.exports = app;
