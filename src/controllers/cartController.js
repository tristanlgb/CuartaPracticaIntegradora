const Cart = require('../models/Cart');
const Product = require('../models/Product');
const Ticket = require('../models/Ticket');
const { sendMail } = require('../utils/mailer');
const { AppError, errorDictionary } = require('../utils/errorHandler');

// Add product to cart
exports.addProductToCart = async (req, res) => {
    try {
        const { cid, pid } = req.params;
        const { quantity } = req.body;

        const product = await Product.findById(pid);
        if (req.user.role === 'premium' && product.owner.toString() === req.user._id.toString()) {
            return res.status(403).json({ message: 'Cannot add your own product to cart' });
        }

        const cart = await Cart.findById(cid);
        const productIndex = cart.products.findIndex(p => p.product.toString() === pid);

        if (productIndex !== -1) {
            cart.products[productIndex].quantity += quantity;
        } else {
            cart.products.push({ product: pid, quantity });
        }

        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json(errorDictionary.CART_ADD_ERROR);
    }
};

// Remove product from cart
exports.removeProductFromCart = async (req, res) => {
    try {
        const { cid, pid } = req.params;

        const cart = await Cart.findById(cid);
        cart.products = cart.products.filter(p => p.product.toString() !== pid);

        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json(errorDictionary.CART_REMOVE_ERROR);
    }
};

// Update product quantity in cart
exports.updateProductQuantity = async (req, res) => {
    try {
        const { cid, pid } = req.params;
        const { quantity } = req.body;

        const cart = await Cart.findById(cid);
        const productIndex = cart.products.findIndex(p => p.product.toString() === pid);

        if (productIndex !== -1) {
            cart.products[productIndex].quantity = quantity;
            await cart.save();
            res.json({ status: 'success', payload: cart });
        } else {
            res.status(404).json({ status: 'error', message: 'Product not found in cart' });
        }
    } catch (err) {
        res.status(500).json(errorDictionary.CART_UPDATE_ERROR);
    }
};

// Clear cart
exports.clearCart = async (req, res) => {
    try {
        const { cid } = req.params;

        const cart = await Cart.findById(cid);
        cart.products = [];
        await cart.save();
        res.json({ status: 'success', payload: cart });
    } catch (err) {
        res.status(500).json(errorDictionary.CART_CLEAR_ERROR);
    }
};

// Purchase products in cart
exports.purchaseCart = async (req, res) => {
    try {
        const { cid } = req.params;

        const cart = await Cart.findById(cid).populate('products.product');
        const unavailableProducts = cart.products.filter(p => !p.product.isAvailable);
        const amount = cart.products.reduce((total, p) => total + (p.product.price * p.quantity), 0);

        const newTicket = new Ticket({
            code: Math.random().toString(36).substring(7),
            purchase_datetime: new Date(),
            amount,
            purchaser: req.user.email
        });
        await newTicket.save();

        cart.products = cart.products.filter(p => !unavailableProducts.includes(p.product._id));
        await cart.save();

        sendMail(req.user.email, 'Purchase Confirmation', 'Thank you for your purchase');

        res.json({ status: 'success', payload: newTicket, unavailableProducts });
    } catch (err) {
        res.status(500).json({ status: 'error', message: err.message });
    }
};
