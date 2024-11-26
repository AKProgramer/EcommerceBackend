const mongoose = require('mongoose');

// Define the OrderItem schema
const orderItemSchema = new mongoose.Schema({
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'Product', // Assuming you have an Item model
  },
  quantity: {
    type: Number,
    required: true,
    min: 1,
  }
});
const orderSchema = new mongoose.Schema({
    addressId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: 'Address', // Assuming you have an Address model
    },
    email: {
      type: String,
      required: true,
    },
    items: {
      type: [orderItemSchema],
      required: true,
    },
    totalCost: {
      type: Number,
      required: true,
    },
    status: {
      type: String,
      enum: ['PENDING', 'CONFIRMED', 'READYFORPICKUP', 'CANCELLED'],
      default: 'PENDING',
    },
    paymentMethod: {
      type: String,
      enum: ['CASH', 'EASYPAISA', 'JAZZCASH'],
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  });
  
  const Order = mongoose.model('Order', orderSchema);
  
  module.exports = Order;