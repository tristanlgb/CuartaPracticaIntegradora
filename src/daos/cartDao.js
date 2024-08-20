const Cart = require('../models/Cart');

const getCartById = async (cartId) => {
  return await Cart.findById(cartId).populate('products.product');
};

const updateCartProducts = async (cartId, products) => {
  return await Cart.findByIdAndUpdate(cartId, { products }, { new: true });
};

const updateCartProductQuantity = async (cartId, productId, quantity) => {
  const cart = await Cart.findById(cartId);
  const productIndex = cart.products.findIndex(p => p.product.toString() === productId);
  if (productIndex >= 0) {
    cart.products[productIndex].quantity = quantity;
    await cart.save();
  }
  return cart;
};

const deleteProductFromCart = async (cartId, productId) => {
  const cart = await Cart.findById(cartId);
  cart.products = cart.products.filter(p => p.product.toString() !== productId);
  await cart.save();
  return cart;
};

const deleteAllProductsFromCart = async (cartId) => {
  const cart = await Cart.findById(cartId);
  cart.products = [];
  await cart.save();
  return cart;
};

module.exports = {
  getCartById,
  updateCartProducts,
  updateCartProductQuantity,
  deleteProductFromCart,
  deleteAllProductsFromCart,
};