const mongoose = require('mongoose');

const addressSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  fullName: {
    type: String,
    required: true,
  },
  mobileNumber: {
    type: String,
    required: true
  },
  province: {
    type: String,
    required: true,
  },
  city: {
    type: String,
    required: true,
  },
  area: {
    type: String,
    required: true,
  },
  address: {
    type: String,
    required: true,
  },
  landmark: {
    type: String,
  },
  label: {
    type: String,
    enum: ['Home', 'Office'],
    default: 'Home',
  },
  isDefault: {
    type: Boolean,
    default: false,
  }
 
});

const Address = mongoose.model('Address', addressSchema);

module.exports = Address;
