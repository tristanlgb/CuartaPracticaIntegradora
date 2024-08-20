const { connect } = require('mongoose');

exports.connectDB = () => {
    connect('mongodb+srv://tristanlgb:<hola123>@pokemons.gobj7y1.mongodb.net/Pokemons?retryWrites=true&w=majority', {
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(() => console.log('DB connected'))
    .catch(err => console.error('DB connection error:', err));
};