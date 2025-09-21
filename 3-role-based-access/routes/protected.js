const express = require('express');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

const router = express.Router();

// Example user-only route
router.get('/user-dashboard', authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}! Role: ${req.user.role}` });
});

// Example admin-only route
router.get('/admin-panel', authenticateToken, authorizeRoles('admin'), (req, res) => {
  res.json({ message: `Hello Admin ${req.user.username}, confidential data inside.` });
});

module.exports = router;
