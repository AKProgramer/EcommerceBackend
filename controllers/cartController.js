const Cart = require('../models/Cart');
const Product = require('../models/Product')
module.exports.addItemToCart = async (req, res) => {
    
    try {
        const { userId, productId, quantity } = req.body;
        const cart = await Cart.findOne({ userId });
        if (cart) {
            const item = cart.items.find(item => item.productId == productId);
            if (item) {
                item.quantity += quantity;
            } else {
                cart.items.push({ productId, quantity });
            }
            await cart.save();
            if(item){
              
                res.status(201).json({cart : cart, isAdded : true});
            }
            else{
            res.status(201).json({cart : cart, isAdded : false});
        }
        } else {
            const product = await Product.findById(productId);
            const newCart = new Cart({
                userId,
                items: [{ productId, quantity }],
            });
            await newCart.save();
            res.status(201).json({car : newCart, isAdded : false});
        }
    } catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to add item to cart' });
    }
}
module.exports.removeItemFromCart = async (req, res) => {
    try {
        const { userId, productId } = req.body;
        const cart = await Cart.findOne({ userId });
        if (cart) {
            cart.items = cart.items.filter(item => item.productId != productId);
            await cart.save();
            res.status(200).json(cart);
        } else {
            res.status(404).json({ error: 'Cart not found' });
        }
    } catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to remove item from cart' });
    }
}
module.exports.removeAllItemsFromCart = async (req, res) => {
    try {
        const { userId } = req.body;
        const cart = await Cart.findOne
        ({ userId });
        if (cart) {
            cart.items = [];
            await cart.save();
            res.status(200).json(cart);
        } else {
            res.status(404).json({ error: 'Cart not found' });
        }
    }
    catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to remove all items from cart' });
    }
}
module.exports.getCartByUserId = async (req, res) => {
    try {
        const { userId } = req.params;
        const cart = await Cart.findOne({ userId }).populate('items.productId');
        if (cart) {
            res.status(200).json(cart);
        } else {
            const newUserCart = {
                items: []
            };
            res.status(200).json(newUserCart);
        }
    }
    catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to get cart' });
    }
}
module.exports.getItemsinCart = async (req, res) => {
    const userId = req.query.userId;
    try {
        const cart = await Cart.findOne({ userId }).populate('items.productId');
        if (cart) {
            res.status(200).json(cart.items.length);
        } else {
            res.status(200).json(0);
        }
    } catch (error) {
        console.log(error.message);
        res.status(500).json({ error: 'Failed to get items in cart' });
    }
}

