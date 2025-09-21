// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 12;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';

// Temporary in-memory store (replace with a DB in real apps)
const users = new Map();

// Register new user
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    if (users.has(username)) return res.status(409).json({ error: 'user already exists' });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    users.set(username, { hash });

    return res.status(201).json({ message: 'user registered successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Login user
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const user = users.get(username);
    if (!user) return res.status(401).json({ error: 'invalid credentials' });

    const match = await bcrypt.compare(password, user.hash);
    if (!match) return res.status(401).json({ error: 'invalid credentials' });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal error' });
  }
});

// Middleware to protect routes
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expect "Bearer <token>"
  if (!token) return res.status(401).json({ error: 'missing token' });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'invalid or expired token' });
    req.user = payload;
    next();
  });
}

// Example protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: `Hello ${req.user.username}, you accessed protected data.` });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
