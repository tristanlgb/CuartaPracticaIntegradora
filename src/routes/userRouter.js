const express = require('express');
const { getUsers, getUser, createUser, updateUser, deleteUser, changeUserRole } = require('../controllers/userController');
const { authenticateToken, authorizeRoles } = require('../middlewares/auth');
const upload = require('../middlewares/uploader');
const User = require('../models/User');

const router = express.Router();

// Admin-only routes
router.get('/', authenticateToken, authorizeRoles('admin'), getUsers);
router.get('/:uid', authenticateToken, authorizeRoles('admin'), getUser);
router.post('/', authenticateToken, authorizeRoles('admin'), createUser);
router.put('/:uid', authenticateToken, authorizeRoles('admin'), updateUser);
router.delete('/:uid', authenticateToken, authorizeRoles('admin'), deleteUser);

// Route to change user role to premium
router.post('/premium/:uid', authenticateToken, async (req, res) => {
  const { uid } = req.params;

  try {
    const user = await User.findById(uid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if required documents are uploaded
    const requiredDocs = ['Identification', 'Proof of address', 'Proof of account status'];
    const uploadedDocs = user.documents.map(doc => doc.name);

    const missingDocs = requiredDocs.filter(doc => !uploadedDocs.includes(doc));

    if (missingDocs.length > 0) {
      return res.status(400).json({
        error: 'You must upload all required documents to become a premium user',
        missingDocuments: missingDocs
      });
    }

    user.role = 'premium';
    await user.save();
    res.status(200).json({ message: 'User upgraded to premium' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route to upload documents for a user
router.post('/:uid/documents', authenticateToken, upload.fields([{ name: 'document' }]), async (req, res) => {
  const { uid } = req.params;

  try {
    const user = await User.findById(uid);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (req.files && req.files['document']) {
      req.files['document'].forEach(file => {
        user.documents.push({
          name: file.originalname,
          reference: file.path
        });
      });

      await user.save();
      res.status(200).json({ message: 'Documents uploaded successfully', documents: user.documents });
    } else {
      res.status(400).json({ error: 'No documents uploaded' });
    }
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;

