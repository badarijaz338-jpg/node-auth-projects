const express = require('express');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

const app = express();
app.use(express.json());

app.use('/auth', authRoutes);
app.use('/protected', protectedRoutes);

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`🚀 Role-based Access server running at http://localhost:${PORT}`);
});
