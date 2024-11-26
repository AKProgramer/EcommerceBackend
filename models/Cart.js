const mongoose = require('mongoose');
const cartItemSchema = require('./CartItem')
const cartSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: [cartItemSchema],
    createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Cart', cartSchema);