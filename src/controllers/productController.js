const Product = require('../models/Product');
const { AppError, errorDictionary } = require('../utils/errorHandler');
const { productService } = require('../services');

class ProductController {
    getProducts = async (req, res) => {
        try {
            const { limit = 10, page = 1, sort, query } = req.query;
            const skip = (page - 1) * limit;
            const sortOrder = sort === 'asc' ? 1 : -1;

            const filter = query ? { category: query } : {};

            const products = await Product.find(filter)
                .sort(sort ? { price: sortOrder } : {})
                .skip(skip)
                .limit(Number(limit));

            const total = await Product.countDocuments(filter);
            const totalPages = Math.ceil(total / limit);

            res.json({
                status: 'success',
                payload: products,
                totalPages,
                prevPage: page > 1 ? page - 1 : null,
                nextPage: page < totalPages ? page + 1 : null,
                page: Number(page),
                hasPrevPage: page > 1,
                hasNextPage: page < totalPages,
                prevLink: page > 1 ? `/products?limit=${limit}&page=${page - 1}&sort=${sort}&query=${query}` : null,
                nextLink: page < totalPages ? `/products?limit=${limit}&page=${page + 1}&sort=${sort}&query=${query}` : null
            });
        } catch (err) {
            res.status(500).json({ status: 'error', message: err.message });
        }
    }

    createProduct = async (req, res) => {
        const { name, price, category, stock } = req.body;
        const owner = req.user.role === 'premium' ? req.user._id : 'admin';

        try {
            const newProduct = await productService.createProduct({ name, price, category, stock, owner });
            res.status(201).json({ status: 'success', data: newProduct });
        } catch (err) {
            res.status(500).json({ status: 'error', message: err.message });
        }
    }

    deleteProduct = async (req, res) => {
        const { id } = req.params;
        const product = await productService.getProductById(id);

        if (!product) {
            return res.status(404).json(errorDictionary.PRODUCT_NOT_FOUND);
        }

        if (req.user.role !== 'admin' && product.owner.toString() !== req.user._id.toString()) {
            return res.status(403).json({ message: 'Not authorized to delete this product' });
        }

        await productService.deleteProduct(id);
        res.status(200).json({ status: 'success', message: 'Product deleted' });
    }
}

module.exports = new ProductController();
