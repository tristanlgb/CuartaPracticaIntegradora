const request = require('supertest');
const { expect } = require('chai');
const app = require('../server');

describe('Cart Router', function () {

  it('should retrieve a list of carts', async function () {
    const res = await request(app).get('/api/carts');
    expect(res.status).to.equal(200);
    expect(res.body).to.be.an('array');
  });

  it('should add a product to the cart', async function () {
    const cartId = '60c72b2f9b1e8a001f5edfb4'; // Example ID, replace with a valid one
    const productData = {
      pid: '60c72b2f9b1e8a001f5edfb3', // Example product ID
      quantity: 2
    };

    const res = await request(app)
      .post(`/api/carts/${cartId}`)
      .send(productData)
      .set('Accept', 'application/json');

    expect(res.status).to.equal(200);
    expect(res.body).to.be.an('object');
    expect(res.body.products).to.be.an('array');
  });

  it('should remove a product from the cart', async function () {
    const cartId = '60c72b2f9b1e8a001f5edfb4'; // Example ID, replace with a valid one
    const productId = '60c72b2f9b1e8a001f5edfb3'; // Example product ID

    const res = await request(app)
      .delete(`/api/carts/${cartId}/products/${productId}`);

    expect(res.status).to.equal(200);
  });
});
