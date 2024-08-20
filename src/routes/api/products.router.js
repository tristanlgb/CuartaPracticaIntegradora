const express = require('express');
const { getProducts } = require('../daos/productDao');

const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const page = parseInt(req.query.page) || 1;
    const sort = req.query.sort || null;
    const query = req.query.query ? { category: req.query.query } : {};

    const { products, total } = await getProducts(query, limit, page, sort);

    const totalPages = Math.ceil(total / limit);
    const response = {
      status: 'success',
      payload: products,
      totalPages,
      prevPage: page > 1 ? page - 1 : null,
      nextPage: page < totalPages ? page + 1 : null,
      page,
      hasPrevPage: page > 1,
      hasNextPage: page < totalPages,
      prevLink: page > 1 ? `/api/products?limit=${limit}&page=${page-1}&sort=${sort}&query=${req.query.query}` : null,
      nextLink: page < totalPages ? `/api/products?limit=${limit}&page=${page+1}&sort=${sort}&query=${req.query.query}` : null,
    };

    res.json(response);
  } catch (error) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

module.exports = router;