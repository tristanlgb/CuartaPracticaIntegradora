const { Router } = require('express');
const authRouter = require('./authRouter');
const cartRouter = require('./cartRouter');
const productRouter = require('./productRouter');
const userRouter = require('./userRouter');
const mockingRouter = require('./mockingRouter');
const sampleRouter = require('./sampleRouter');
const loginRouter = require('./loginRouter'); // Add loginRouter

const router = Router();

router.use('/auth', authRouter);
router.use('/carts', cartRouter);
router.use('/products', productRouter);
router.use('/users', userRouter);
router.use('/mock', mockingRouter);
router.use('/test', sampleRouter);
router.use(loginRouter); // Use loginRouter

module.exports = router;
