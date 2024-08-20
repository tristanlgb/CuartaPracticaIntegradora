const Product = require('../models/Product');

const getProducts = async (query, limit, page, sort) => {
  const skip = (page - 1) * limit;
  const sortOption = sort === 'asc' ? { price: 1 } : { price: -1 };
  const products = await Product.find(query)
    .limit(limit)
    .skip(skip)
    .sort(sortOption);
  const total = await Product.countDocuments(query);
  return { products, total };
};

module.exports = { getProducts };