const { Router } = require('express');
const generatePokemons = require('../utils/mocking');

const router = Router();

router.get('/mockingpokemons', (req, res) => {
  const pokemons = generatePokemons();
  res.json(pokemons);
});

module.exports = router;