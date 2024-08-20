const request = require('supertest');
const { expect } = require('chai');
const app = require('../server');

describe('Session Router', function () {

  it('should log in a user', async function () {
    const loginData = {
      email: 'testuser@example.com',
      password: 'testpassword'
    };

    const res = await request(app)
      .post('/auth/login')
      .send(loginData)
      .set('Accept', 'application/json');

    expect(res.status).to.equal(200);
    expect(res.body).to.be.an('object');
    expect(res.body.message).to.equal('Logged in successfully');
  });

  it('should register a new user', async function () {
    const registerData = {
      username: 'newuser',
      password: 'newpassword'
    };

    const res = await request(app)
      .post('/auth/register')
      .send(registerData)
      .set('Accept', 'application/json');

    expect(res.status).to.equal(201);
    expect(res.body).to.be.an('object');
    expect(res.body.message).to.equal('User created');
  });

  it('should log out a user', async function () {
    const res = await request(app)
      .post('/auth/logout');

    expect(res.status).to.equal(200);
    expect(res.body.message).to.equal('Logged out successfully');
  });
});
