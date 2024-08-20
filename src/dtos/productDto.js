class ProductDto {
  constructor(product) {
    this.name = product.name;
    this.description = product.description;
    this.price = product.price;
    this.stock = product.stock;
    this.category = product.category;
  }
}

module.exports = ProductDto;
