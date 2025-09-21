// 1-hash-auth/server.js
const express = require('express');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.use(express.json());

const users = new Map(); // In-memory store
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 12;

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });

  if (users.has(username)) return res.status(409).json({ error: 'user already exists' });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  users.set(username, { hash });

  res.status(201).json({ message: 'user registered with hashed password' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);

  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const match = await bcrypt.compare(password, user.hash);
  if (!match) return res.status(401).json({ error: 'invalid credentials' });

  res.json({ message: `Welcome ${username}, login successful!` });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 Hash Auth server running on http://localhost:${PORT}`));
