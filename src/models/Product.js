const { Schema, model } = require('mongoose');

const ProductSchema = new Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    category: { type: String, required: true },
    stock: { type: Number, default: 0 },
    available: { type: Boolean, default: true },
    owner: { type: Schema.Types.ObjectId, ref: 'User', default: null }
});

module.exports = model('Product', ProductSchema);