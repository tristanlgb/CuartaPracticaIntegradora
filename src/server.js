const express = require('express');
const { engine } = require('express-handlebars');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('./config/passport');
const config = require('./config/config');
const { connectDB } = require('./config/index');
const { requestLogger, errorLogger } = require('./middlewares/logger');
const compression = require('compression');
const productRoutes = require('./routes/productRoutes');
const cartRoutes = require('./routes/cartRoutes');
const viewRoutes = require('./routes/viewRoutes');
const authRoutes = require('./routes/authRoutes');
const mockingRouter = require('./routes/mockingRouter');
const { errorHandler } = require('./utils/errorHandler');

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware setup
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(compression()); // Add compression middleware

app.use(session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// View engine setup
app.engine('hbs', engine({
  extname: '.hbs',
  defaultLayout: 'main',
}));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

// Connect to MongoDB
connectDB();

// Logger middleware
app.use(requestLogger);

// Route setup
app.use('/', viewRoutes);
app.use('/api/products', productRoutes);
app.use('/api/carts', cartRoutes);
app.use('/auth', authRoutes);
app.use('/api', mockingRouter);

// Error handling middleware
app.use(errorLogger);
app.use(errorHandler);

// Start the server
app.listen(PORT, err => {
  if (err) {
    console.log('Error:', err);
  } else {
    console.log(`Listening on port: ${PORT}`);
  }
});
