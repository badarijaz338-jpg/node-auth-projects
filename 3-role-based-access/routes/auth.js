const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const users = require('../users/userStore');
require('dotenv').config();

const router = express.Router();

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 12;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';

router.post('/register', async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  if (users.has(username)) return res.status(409).json({ error: 'user already exists' });

  const hash = await bcrypt.hash(password, SALT_ROUNDS);
  users.set(username, { hash, role: role || 'user' });

  res.status(201).json({ message: 'user registered successfully' });
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });

  const match = await bcrypt.compare(password, user.hash);
  if (!match) return res.status(401).json({ error: 'invalid credentials' });

  const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

module.exports = router;
