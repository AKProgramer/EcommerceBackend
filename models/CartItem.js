const mongoose = require('mongoose');
const cartItemSchema = mongoose.Schema({
    productId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:'Product',
        required:true
    },
    quantity:{
        type:Number,
        required:true
    },
    addedAt:{
        type:Date,
        default:Date.now
    }
})
module.exports = cartItemSchema;