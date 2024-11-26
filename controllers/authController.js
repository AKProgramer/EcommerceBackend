const User = require('../models/User')
const Cart = require('../models/Cart')
const Order = require('../models/Order')
const Address = require('../models/Address')
const jwt = require('jsonwebtoken')
const fs = require('fs');
const path = require('path');

const createToken=(id)=>{
    return jwt.sign({id}, '23456323456@34654456',{
        expiresIn : '1h'
    });
}
module.exports.signup_post =async (req,res)=>{
    const {username, email, password,role} = req.body;
    try{
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            if (existingUser.authProvider === 'google') {
                // Update the password for the existing Google user
                existingUser.password = password;
                existingUser.username = username;
                await existingUser.save();
                
                const token = createToken(existingUser._id);
                return res.status(201).json({ userId: existingUser._id, token, message: 'Password updated for Google user' });
            } else {
                // Email is already registered with a different provider
                return res.status(409).json({ errors: { email: 'Email is already registered' } });  
            }
        }

        const user = await User.create({username, email, password,role });
        const token = createToken(user._id);
        res.status(201).json({ userId: user._id, token, role : user.role });
    }
    catch(err)
    {
        console.log(err)
        res.status(400).json({ errors: err });
    }
}
module.exports.login_post =async (req, res)=>{
    const {email, password} = req.body;
  try
  {
    const user = await User.login(email, password);
    const token = createToken(user._id);
    res.status(200).json({ userId: user._id, token, role : user.role });
  }
  catch(err)
  {
    let errors = {email : '', password : ''}; 
    if(err.message === 'incorrect email')
    {
        errors.email = 'Email is not registered';
    }
    if(err.message === 'auth using google')
    {
        errors.password = 'Please signup first or login using google';
    }
    if(err.message === 'incorrect password')
    {
        errors.password = 'Password is incorrect';
    }
    res.status(400).json({ errors });
  }
   
}
module.exports.upload_image = async (req, res)=>{
    const {userId} = req.body;
    try{
        const user = await User.findOne({ _id: userId });

        // Check if the user already has an image and it contains 'uploads'
        if (user.image && user.image.includes('uploads')) {
            const imagePath = path.resolve(__dirname, '..', user.image.replace(/\\/g, '/'));

            // Check if the file exists before attempting to delete it
            if (fs.existsSync(imagePath)) {
                fs.unlink(imagePath, (err) => {
                    if (err) {
                        console.error('Failed to delete existing image:', err);
                    } else {
                        console.log('Existing image deleted:', imagePath);
                    }
                });
            } else {
                console.log('Image file does not exist:', imagePath);
            }
        }
         user.image = req.file.path;
         await user.save();
         return res.status(200).json({ image: user.image});
    }
    catch(err)
    {
        console.log(err);
        res.status(500).json({error : 'Failed to upload image'});
    }
}
module.exports.get_user_by_id = async (req, res)=>{
    const {userId} = req.params;
    try{
        const user = await User.findOne({_id : userId});
        res.status(200).json(user);
    }
    catch(err)
    {
        console.log(err);
        res.status(500).json({error : 'Failed to get user'});
    }
}
module.exports.getTotalUserCount = async (req, res)=>{
    try{
        const count = await User.countDocuments({role : 'user'});
        res.status(200).json({count});
    }
    catch(err)
    {
        console.log(err);
        res.status(500).json({error : 'Failed to get user count'});
    }
}
module.exports.getAllUsers = async (req, res) => {
    try {
      // Fetch all users with the role 'user'
      const users = await User.find({ role: 'user' }).select('_id image username email role');
      // Create an array to hold user data
      const userData = await Promise.all(users.map(async (user) => {
        // Find cart for each user and populate items
        const cart = await Cart.findOne({ userId: user._id }).populate('items.productId');
        const cartItemsCount = cart ? cart.items.reduce((total, item) => total + item.quantity, 0) : 0;
        const orderCount = cart ? cart.items.length : 0;
  
        // Return user details with cart items
        return {
          _id: user._id,
          image: user.image,
          username: user.username,
          email: user.email,
          orderCount: orderCount,
          cartItemsCount: cartItemsCount,
        };
      }));
  
      res.json(userData);
    } catch (err) {
      console.log(err);
      res.status(500).json({ error: 'Failed to get users' });
    }
  };
  
module.exports.deleteUser = async (req, res) => {
    const { userId } = req.params;
    try {
        // Find the user by ID
        const user = await User.findOne({ _id: userId });

        // Check if the user has an image and it contains 'uploads'
        if (user.image && user.image.includes('uploads')) {
            const imagePath = path.resolve(__dirname, '..', user.image.replace(/\\/g, '/'));

            // Check if the file exists before attempting to delete it
            if (fs.existsSync(imagePath)) {
                fs.unlink(imagePath, (err) => {
                    if (err) {
                        console.error('Failed to delete image:', err);
                    } else {
                        console.log('Image deleted:', imagePath);
                    }
                });
            } else {
                console.log('Image file does not exist:', imagePath);
            }
        }

        // Delete the user's cart
        await Cart.deleteOne({ userId: userId });

        // Delete the user's addresses
        const addresses = await Address.find({ userId: userId });
        const addressIds = addresses.map(address => address._id);
        await Address.deleteMany({ userId: userId });

        // Delete orders related to the addresses
        await Order.deleteMany({ addressId: { $in: addressIds } });

        // Delete the user
        await User.deleteOne({ _id: userId });

        res.status(200).json({ message: 'User and related data deleted' });
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: 'Failed to delete user and related data' });
    }
};
module.exports.google_auth_callback = async (req, res) => {
    const { token, user } = req.user;
    res.redirect(`http://localhost:3000?token=${token}&userId=${user._id}`);
};