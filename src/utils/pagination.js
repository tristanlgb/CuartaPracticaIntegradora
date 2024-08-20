const buildPagination = (totalItems, currentPage, pageSize) => {
    const totalPages = Math.ceil(totalItems / pageSize);
    const hasPrevPage = currentPage > 1;
    const hasNextPage = currentPage < totalPages;
  
    return {
      totalPages,
      currentPage,
      hasPrevPage,
      hasNextPage,
      prevPage: hasPrevPage ? currentPage - 1 : null,
      nextPage: hasNextPage ? currentPage + 1 : null,
    };
  };
  
  module.exports = { buildPagination };