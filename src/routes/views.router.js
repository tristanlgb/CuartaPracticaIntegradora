const express = require('express');
const { getProducts } = require('../daos/productDao');
const { getCartById } = require('../daos/cartDao');
const Product = require('../models/Product');

const router = express.Router();

router.get('/products', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const page = parseInt(req.query.page) || 1;
    const sort = req.query.sort || null;
    const query = req.query.query ? { category: req.query.query } : {};

    const { products, total } = await getProducts(query, limit, page, sort);

    const totalPages = Math.ceil(total / limit);

    res.render('products', {
      products,
      totalPages,
      page,
      limit,
      sort,
      query: req.query.query,
    });
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

router.get('/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    res.render('product', { product });
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

router.get('/carts/:cid', async (req, res) => {
  try {
    const cart = await getCartById(req.params.cid);
    res.render('cart', { cart });
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = router;