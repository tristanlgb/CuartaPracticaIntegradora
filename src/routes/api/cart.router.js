const express = require('express');
const {
  getCartById,
  updateCartProducts,
  updateCartProductQuantity,
  deleteProductFromCart,
  deleteAllProductsFromCart,
} = require('../daos/cartDao');

const router = express.Router();

router.get('/:cid', async (req, res) => {
  try {
    const cart = await getCartById(req.params.cid);
    res.json(cart);
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

router.put('/:cid', async (req, res) => {
  try {
    const updatedCart = await updateCartProducts(req.params.cid, req.body.products);
    res.json(updatedCart);
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

router.put('/:cid/products/:pid', async (req, res) => {
  try {
    const updatedCart = await updateCartProductQuantity(req.params.cid, req.params.pid, req.body.quantity);
    res.json(updatedCart);
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

router.delete('/:cid/products/:pid', async (req, res) => {
  try {
    const updatedCart = await deleteProductFromCart(req.params.cid, req.params.pid);
    res.json(updatedCart);
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

router.delete('/:cid', async (req, res) => {
  try {
    const updatedCart = await deleteAllProductsFromCart(req.params.cid);
    res.json(updatedCart);
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = router;