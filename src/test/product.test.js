const request = require('supertest');
const { expect } = require('chai');
const app = require('../server'); // Import the Express app

describe('Product Router', function () {

  it('should retrieve a list of products', async function () {
    const res = await request(app).get('/api/products');
    expect(res.status).to.equal(200);
    expect(res.body).to.be.an('array');
  });

  it('should create a new product', async function () {
    const newProduct = {
      name: 'Charizard',
      price: 20,
      category: 'Fire',
      stock: 50,
      available: true
    };

    const res = await request(app)
      .post('/api/products')
      .send(newProduct)
      .set('Accept', 'application/json');

    expect(res.status).to.equal(201);
    expect(res.body).to.be.an('object');
    expect(res.body.name).to.equal('Charizard');
  });

  it('should delete a product', async function () {
    const productId = '60c72b2f9b1e8a001f5edfb3'; // Example ID, replace with a valid one

    const res = await request(app)
      .delete(`/api/products/${productId}`);

    expect(res.status).to.equal(200);
  });
});
