var express = require('express')
var authRoutes = require('./routes/authRoutes')
const productRoutes = require('./routes/productRoutes')
const categoryRoutes = require('./routes/categoryRoutes')
const orderRoutes = require('./routes/orderRoutes')
const addressRoutes = require('./routes/addressRoutes')
const brandRoutes = require('./routes/brandRoutes')
const cartRoutes = require('./routes/cartRoutes');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const cors = require('cors')
require('dotenv').config();
const User = require('./models/User');
const app = express()
const jwt = require('jsonwebtoken')
//generate jwt for user logged in using auth2.0
const createToken=(id)=>{
    return jwt.sign({id}, '23456323456@34654456',{
        expiresIn : '1h'
    });
}
// Check for required environment variables
const requiredEnvVars = ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_CALLBACK_URL', 'DATABASE_URI'];
const missingEnvVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingEnvVars.length > 0) {
    console.log(`\n[ERROR] Missing environment variables: ${missingEnvVars.join(', ')}\n`);
    console.log('Please add the missing credentials to your .env file.');
    process.exit(1); 
}
// middleware
    app.use(cors())
    app.use(express.static('uploads'));
    app.use(express.json());
    // middlewares for auth2.0 with google
    app.use(session({
        secret: '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',
        resave: false,
        saveUninitialized: true,
    }));
    
    app.use(passport.initialize());
    app.use(passport.session());
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },async (accessToken, refreshToken, profile, done) => {
    try{
        let user = await User.findOne({  email : profile._json.email});
        if(!user)
        {
            user = await User.create({
                username: profile._json.given_name,
                email: profile._json.email,
                role : 'user',
                image : profile._json.picture,
                authProvider: 'google',
                authProviderId: profile._json.sub
            });
        }
        const token = createToken(user._id);

        return done(null, {user, token});
    }
    catch(error)
    {
        return done(error, null);
    }
    }));
    
    passport.serializeUser((user, done) => {
        done(null, user);
    });
    
    passport.deserializeUser((user, done) => {
        done(null, user);
    });

// database connection
const dbURI = process.env.DATABASE_URI;
mongoose.connect(dbURI)
    .then((result) => console.log('connected to db'))
    .catch((err) => console.log(err));

app.use(authRoutes)
app.use(productRoutes)
app.use(categoryRoutes)
app.use(cartRoutes)
app.use(orderRoutes)
app.use(addressRoutes)
app.use(brandRoutes)
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
