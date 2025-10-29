/**
 * Construlogix - Backend (server.js)
 * Node.js + Express + SQLite (better-sqlite3)
 * Features: JWT auth, roles (admin, bodeguero, supervisor), materials, movements, QR generation
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const QRCode = require('qrcode');

const JWT_SECRET = process.env.JWT_SECRET || 'construlogix_secret_change_in_prod';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '8h';

const app = express();
app.use(cors());
app.use(bodyParser.json());

// DB init
const dbPath = path.join(__dirname, 'db.sqlite');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Create tables
db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE,
  password TEXT,
  name TEXT,
  role TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS materials (
  id TEXT PRIMARY KEY,
  code TEXT UNIQUE,
  name TEXT,
  unit TEXT,
  unit_price REAL,
  stock REAL DEFAULT 0,
  location TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS movements (
  id TEXT PRIMARY KEY,
  material_id TEXT,
  type TEXT,
  quantity REAL,
  date TEXT,
  project TEXT,
  provider_or_dest TEXT,
  user TEXT,
  note TEXT
)`).run();

// Seed users
const seedUser = (username, password, name, role) => {
  const existing = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!existing) {
    const hashed = bcrypt.hashSync(password, 10);
    db.prepare('INSERT INTO users (id, username, password, name, role) VALUES (?, ?, ?, ?, ?)').run(uuidv4(), username, hashed, name, role);
    console.log('Seeded user', username);
  }
};
seedUser('admin', 'admin', 'Administrador', 'admin');
seedUser('bodeguero', 'bodega123', 'Bodeguero', 'bodeguero');
seedUser('supervisor', 'super123', 'Supervisor', 'supervisor');

// Helpers
function generateToken(user) {
  const payload = { id: user.id, username: user.username, name: user.name, role: user.role };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Token mal formado' });
  const token = parts[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (err) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'No autorizado' });
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Permisos insuficientes' });
    next();
  };
}

// Public routes
app.post('/api/register', async (req, res) => {
  const { username, password, name = '', role = 'bodeguero' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username y password son requeridos' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    const id = uuidv4();
    db.prepare('INSERT INTO users (id, username, password, name, role) VALUES (?, ?, ?, ?, ?)').run(id, username, hashed, name, role);
    const user = db.prepare('SELECT id, username, name, role FROM users WHERE id = ?').get(id);
    const token = generateToken(user);
    res.json({ user, token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!u) return res.status(401).json({ error: 'Credenciales inválidas' });
  const match = bcrypt.compareSync(password, u.password);
  if (!match) return res.status(401).json({ error: 'Credenciales inválidas' });
  const user = { id: u.id, username: u.username, name: u.name, role: u.role };
  const token = generateToken(user);
  res.json({ user, token });
});

// Protected routes
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// Materials
app.post('/api/materials', authMiddleware, (req, res) => {
  const { code, name, unit = 'unidad', unit_price = 0, location = '' } = req.body;
  try {
    const id = uuidv4();
    db.prepare('INSERT INTO materials (id, code, name, unit, unit_price, stock, location) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, code, name, unit, unit_price, 0, location);
    const m = db.prepare('SELECT * FROM materials WHERE id = ?').get(id);
    res.json(m);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/materials', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT * FROM materials ORDER BY name').all();
  res.json(rows);
});

app.get('/api/materials/:id', authMiddleware, (req, res) => {
  const m = db.prepare('SELECT * FROM materials WHERE id = ? OR code = ?').get(req.params.id, req.params.id);
  if (!m) return res.status(404).json({ error: 'Material no encontrado' });
  res.json(m);
});

// QR endpoint
app.get('/api/materials/:id/qr', authMiddleware, async (req, res) => {
  const material = db.prepare('SELECT * FROM materials WHERE id = ? OR code = ?').get(req.params.id, req.params.id);
  if (!material) return res.status(404).json({ error: 'Material no encontrado' });
  // The QR points to a friendly URL — you can change domain when deploying
  const qrData = `${process.env.QR_BASE_URL || 'http://localhost:5173'}/material/${encodeURIComponent(material.code)}`;
  try {
    const qr = await QRCode.toDataURL(qrData);
    res.json({ material, qr });
  } catch (err) {
    res.status(500).json({ error: 'Error al generar QR' });
  }
});

// Movements
app.post('/api/movements/entrada', authMiddleware, (req, res) => {
  const { material_id, code, quantity, date = new Date().toISOString(), provider = '', project = '', note = '' } = req.body;
  try {
    const material = db.prepare('SELECT * FROM materials WHERE id = ? OR code = ?').get(material_id, code);
    if (!material) return res.status(404).json({ error: 'Material no encontrado' });
    const id = uuidv4();
    db.prepare('INSERT INTO movements (id, material_id, type, quantity, date, project, provider_or_dest, user, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, material.id, 'entrada', quantity, date, project, provider, req.user.username, note);
    db.prepare('UPDATE materials SET stock = stock + ? WHERE id = ?').run(quantity, material.id);
    const m = db.prepare('SELECT * FROM materials WHERE id = ?').get(material.id);
    res.json({ movementId: id, material: m });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/movements/salida', authMiddleware, requireRole('admin', 'bodeguero'), (req, res) => {
  const { material_id, code, quantity, date = new Date().toISOString(), project = '', dest = '', note = '' } = req.body;
  try {
    const material = db.prepare('SELECT * FROM materials WHERE id = ? OR code = ?').get(material_id, code);
    if (!material) return res.status(404).json({ error: 'Material no encontrado' });
    if (material.stock < quantity) return res.status(400).json({ error: 'Stock insuficiente' });
    const id = uuidv4();
    db.prepare('INSERT INTO movements (id, material_id, type, quantity, date, project, provider_or_dest, user, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, material.id, 'salida', quantity, date, project, dest, req.user.username, note);
    db.prepare('UPDATE materials SET stock = stock - ? WHERE id = ?').run(quantity, material.id);
    const m = db.prepare('SELECT * FROM materials WHERE id = ?').get(material.id);
    res.json({ movementId: id, material: m });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/movements', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT mv.*, mt.name as material_name, mt.code as material_code FROM movements mv LEFT JOIN materials mt ON mv.material_id = mt.id ORDER BY date DESC').all();
  res.json(rows);
});

app.get('/api/summary', authMiddleware, (req, res) => {
  const totalMaterials = db.prepare('SELECT COUNT(*) as c FROM materials').get().c;
  const totalStockValue = db.prepare('SELECT SUM(stock * unit_price) as total FROM materials').get().total || 0;
  const recentMovements = db.prepare('SELECT mv.*, mt.name as material_name FROM movements mv LEFT JOIN materials mt ON mv.material_id = mt.id ORDER BY date DESC LIMIT 10').all();
  res.json({ totalMaterials, totalStockValue, recentMovements });
});

app.get('/api/users', authMiddleware, requireRole('admin'), (req, res) => {
  const rows = db.prepare('SELECT id, username, name, role FROM users ORDER BY username').all();
  res.json(rows);
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Backend running on http://localhost:${PORT}`));