const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    let folder = 'uploads/documents/'; // Default folder

    if (file.fieldname === 'profile') {
      folder = path.join(__dirname, '../../uploads/profiles/');
    } else if (file.fieldname === 'product') {
      folder = path.join(__dirname, '../../uploads/products/');
    }

    cb(null, folder);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ storage });

module.exports = upload;
