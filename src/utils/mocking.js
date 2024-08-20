const { faker } = require('@faker-js/faker');

const generatePokemon = () => ({
  name: faker.animal.type(),
  price: faker.datatype.number({ min: 5, max: 50 }),
  category: faker.helpers.randomize(['Grass', 'Fire', 'Water', 'Electric', 'Fairy', 'Normal', 'Psychic', 'Dragon']),
  stock: faker.datatype.number({ min: 0, max: 100 }),
  available: faker.datatype.boolean()
});

const generatePokemons = (count = 100) => {
  const pokemons = [];
  for (let i = 0; i < count; i++) {
    pokemons.push(generatePokemon());
  }
  return pokemons;
};

module.exports = generatePokemons;