const ProductDto = require('../dtos/productDto');

class ProductRepository {
  constructor(ProductDao) {
    this.productDao = ProductDao;
  }

  async getProducts() {
    const products = await this.productDao.getAll();
    return products.map(product => new ProductDto(product));
  }

  async getProduct(filter) {
    const product = await this.productDao.getBy(filter);
    return new ProductDto(product);
  }

  async createProduct(product) {
    const newProduct = await this.productDao.create(product);
    return new ProductDto(newProduct);
  }

  async updateProduct(id, productToUpdate) {
    const updatedProduct = await this.productDao.update(id, productToUpdate);
    return new ProductDto(updatedProduct);
  }

  async deleteProduct(id) {
    await this.productDao.delete(id);
    return { message: 'Product deleted successfully' };
  }
}

module.exports = ProductRepository;
