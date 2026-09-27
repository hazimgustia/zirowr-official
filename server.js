require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'zirowr-secret';

// ===== DATABASE =====
const adapter = new JSONFile(path.join(__dirname, 'db.json'));
const db = new Low(adapter);

// ===== UPLOAD DIR =====
const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + uuidv4().slice(0, 8) + ext);
  }
});

const upload = multer({
  storage: fileStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp|mp4|webm|mov|avi|zip|rar|7z|pdf|txt|js|json|html|css|md/;
    if (allowed.test(path.extname(file.originalname).toLowerCase())) return cb(null, true);
    cb(new Error('File type tidak didukung'));
  }
});

const avatarUpload = multer({
  storage: fileStorage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = /jpeg|jpg|png|gif|webp/;
    if (allowed.test(path.extname(file.originalname).toLowerCase())) return cb(null, true);
    cb(new Error('Hanya gambar'));
  }
});

// ===== MIDDLEWARE =====
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Visitor counter SEBELUM static
app.use(async (req, res, next) => {
  if (req.path === '/' && req.method === 'GET') {
    try {
      await db.read();
      db.data.stats.visitors = (db.data.stats.visitors || 0) + 1;
      await db.write();
    } catch (e) {}
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));

function authMiddleware(req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer ', '') || req.query.token;
  if (!token) return res.status(401).json({ error: 'Login diperlukan' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token tidak valid' });
  }
}

async function initDB() {
  await db.read();
  if (!db.data) db.data = {};
  db.data.users = db.data.users || [];
  db.data.chats = db.data.chats || [];
  db.data.uploads = db.data.uploads || [];
  db.data.projects = db.data.projects || [];
  db.data.stats = db.data.stats || { visitors: 0 };
  await db.write();
  console.log('✅ Database siap');
}
initDB();

// ============================================================
// AUTH
// ============================================================
app.post('/api/auth/register', async (req, res) => {
  await db.read();
  const { username, email, password, bio } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'Semua field wajib diisi' });
  if (username.length < 3 || username.length > 20)
    return res.status(400).json({ error: 'Username 3-20 karakter' });
  if (!/^[a-zA-Z0-9_]+$/.test(username))
    return res.status(400).json({ error: 'Username hanya huruf, angka, underscore' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password minimal 6 karakter' });
  if (db.data.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(400).json({ error: 'Username sudah dipakai' });
  if (db.data.users.find(u => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: 'Email sudah terdaftar' });

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(), username, email, password: hashed,
    bio: bio || '', avatar: '',
    joinedAt: new Date().toISOString(), reputation: 0
  };
  db.data.users.push(user);
  await db.write();

  const token = jwt.sign({ id: user.id, username, email }, JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({ token, user: { id: user.id, username, email, bio: user.bio, avatar: user.avatar, joinedAt: user.joinedAt, reputation: user.reputation } });
});

app.post('/api/auth/login', async (req, res) => {
  await db.read();
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email & password wajib diisi' });
  const user = db.data.users.find(u =>
    u.email.toLowerCase() === email.toLowerCase() ||
    u.username.toLowerCase() === email.toLowerCase()
  );
  if (!user) return res.status(401).json({ error: 'Akun tidak ditemukan' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Password salah' });
  const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email, bio: user.bio, avatar: user.avatar, joinedAt: user.joinedAt, reputation: user.reputation } });
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  res.json({ id: user.id, username: user.username, email: user.email, bio: user.bio, avatar: user.avatar, joinedAt: user.joinedAt, reputation: user.reputation });
});

app.post('/api/auth/avatar', authMiddleware, avatarUpload.single('avatar'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan' });
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  user.avatar = '/uploads/' + req.file.filename;
  await db.write();
  res.json({ success: true, avatar: user.avatar });
});

// ============================================================
// PROJECTS
// ============================================================
app.get('/api/projects', async (req, res) => {
  await db.read();
  const { search, type, sort } = req.query;
  let projects = db.data.projects.slice();
  if (search) {
    const s = search.toLowerCase();
    projects = projects.filter(p =>
      p.title.toLowerCase().includes(s) ||
      p.description.toLowerCase().includes(s) ||
      p.tags.some(t => t.toLowerCase().includes(s))
    );
  }
  if (type && type !== 'all') projects = projects.filter(p => p.type === type);
  if (sort === 'popular') projects.sort((a, b) => (b.likes || 0) - (a.likes || 0));
  else if (sort === 'downloads') projects.sort((a, b) => (b.downloads || 0) - (a.downloads || 0));
  else projects.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const enriched = projects.map(p => {
    const u = db.data.users.find(x => x.id === p.userId);
    return { ...p, author: u ? { username: u.username, avatar: u.avatar } : { username: 'Unknown', avatar: '' } };
  });
  res.json(enriched);
});

app.get('/api/projects/:id', async (req, res) => {
  await db.read();
  const p = db.data.projects.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Project tidak ditemukan' });
  const u = db.data.users.find(x => x.id === p.userId);
  res.json({ ...p, author: u ? { username: u.username, avatar: u.avatar, bio: u.bio } : null });
});

app.post('/api/projects', authMiddleware, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User tidak ditemukan' });
  const { title, description, type, sourceCode, demoUrl, tags, fileName, fileUrl, language } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'Judul & deskripsi wajib diisi' });

  const project = {
    id: uuidv4(), userId: user.id,
    title: title.slice(0, 100),
    description: description.slice(0, 2000),
    type: type || 'other',
    sourceCode: sourceCode ? String(sourceCode).slice(0, 50000) : '',
    demoUrl: demoUrl ? String(demoUrl).slice(0, 500) : '',
    language: language || 'javascript',
    tags: Array.isArray(tags) ? tags.slice(0, 10).map(t => String(t).slice(0, 30)) : [],
    fileName: fileName || '', fileUrl: fileUrl || '',
    likes: 0, downloads: 0,
    createdAt: new Date().toISOString()
  };
  db.data.projects.push(project);
  user.reputation = (user.reputation || 0) + 5;
  await db.write();
  res.status(201).json(project);
});

app.post('/api/projects/:id/like', authMiddleware, async (req, res) => {
  await db.read();
  const p = db.data.projects.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Project tidak ditemukan' });
  p.likes = (p.likes || 0) + 1;
  await db.write();
  res.json({ success: true, likes: p.likes });
});

app.post('/api/projects/:id/download', async (req, res) => {
  await db.read();
  const p = db.data.projects.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'Project tidak ditemukan' });
  p.downloads = (p.downloads || 0) + 1;
  await db.write();
  res.json({ success: true, downloads: p.downloads });
});

app.delete('/api/projects/:id', authMiddleware, async (req, res) => {
  await db.read();
  const idx = db.data.projects.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Project tidak ditemukan' });
  if (db.data.projects[idx].userId !== req.user.id) return res.status(403).json({ error: 'Tidak diizinkan' });
  db.data.projects.splice(idx, 1);
  await db.write();
  res.json({ success: true });
});

// ============================================================
// STATS / SERVER / UPLOAD / PAYMENT / CHAT
// ============================================================
app.get('/api/stats', async (req, res) => {
  await db.read();
  res.json({
    visitors: db.data.stats.visitors || 0,
    online: io.engine.clientsCount || 0,
    totalChats: db.data.chats.length,
    totalUploads: db.data.uploads.length,
    totalUsers: db.data.users.length,
    totalProjects: db.data.projects.length
  });
});

app.get('/api/server-status', async (req, res) => {
  try {
    if (!process.env.PTERODACTYL_URL || !process.env.PTERODACTYL_API_KEY) {
      return res.json({ online: false, message: 'Pterodactyl belum dikonfigurasi' });
    }
    const r = await fetch(`${process.env.PTERODACTYL_URL}/api/application/servers`, {
      headers: { 'Authorization': `Bearer ${process.env.PTERODACTYL_API_KEY}`, 'Accept': 'application/json' }
    });
    if (!r.ok) throw new Error('API error');
    const data = await r.json();
    const servers = data.data.map(s => ({
      id: s.attributes.id, name: s.attributes.name, status: s.attributes.status,
      memory: s.attributes.limits.memory, disk: s.attributes.limits.disk, cpu: s.attributes.limits.cpu
    }));
    res.json({ online: true, servers });
  } catch (err) {
    res.json({ online: false, message: 'Gagal fetch server' });
  }
});

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File tidak ditemukan' });
  await db.read();
  const fileData = {
    id: uuidv4(),
    filename: req.file.filename,
    originalName: req.file.originalname,
    size: req.file.size,
    mimetype: req.file.mimetype,
    url: '/uploads/' + req.file.filename,
    userId: req.user.id,
    uploadedAt: new Date().toISOString()
  };
  db.data.uploads.push(fileData);
  await db.write();
  res.json({ success: true, file: fileData });
});

app.get('/api/payment-methods', (req, res) => {
  res.json([
    { id: 'dana', name: 'DANA', number: '085194702836', holder: 'Agus Salim', type: 'ewallet', color: '#118eea' },
    { id: 'gopay', name: 'GoPay', number: '085169196159', holder: 'Zirowr Store', type: 'ewallet', color: '#00aed6' },
    { id: 'seabank', name: 'SeaBank', number: '9012345678', holder: 'Zirowr Store', type: 'bank', color: '#ff6a00' }
  ]);
});

app.get('/api/chat/history', async (req, res) => {
  await db.read();
  res.json(db.data.chats.slice(-100));
});

// ============================================================
// GAME LOGIC
// ============================================================
const gameRooms = new Map();

function generateRoomId() {
  return Math.random().toString(36).substring(2, 8).toUpperCase();
}

function getRoomList(gameType) {
  return Array.from(gameRooms.entries())
    .filter(([_, r]) => r.game === gameType && r.players.length < r.maxPlayers && !r.aiMode)
    .map(([id, r]) => ({
      id, game: r.game, players: r.players.length, maxPlayers: r.maxPlayers,
      host: r.hostName || 'Anonim', createdAt: r.createdAt
    }));
}

// ===== CHESS =====
function initChessBoard() {
  return [
    ['br','bn','bb','bq','bk','bb','bn','br'],
    ['bp','bp','bp','bp','bp','bp','bp','bp'],
    [null,null,null,null,null,null,null,null],
    [null,null,null,null,null,null,null,null],
    [null,null,null,null,null,null,null,null],
    [null,null,null,null,null,null,null,null],
    ['wp','wp','wp','wp','wp','wp','wp','wp'],
    ['wr','wn','wb','wq','wk','wb','wn','wr']
  ];
}

function getChessMoves(board, r, c) {
  const piece = board[r][c];
  if (!piece) return [];
  const color = piece[0], type = piece[1];
  const enemy = color === 'w' ? 'b' : 'w';
  const moves = [];

  const slide = (dirs) => {
    for (const [dr, dc] of dirs) {
      let nr = r + dr, nc = c + dc;
      while (nr >= 0 && nr <= 7 && nc >= 0 && nc <= 7) {
        const t = board[nr][nc];
        if (t && t[0] === color) break;
        moves.push([nr, nc]);
        if (t) break;
        nr += dr; nc += dc;
      }
    }
  };

  if (type === 'p') {
    const dir = color === 'w' ? -1 : 1;
    const startRow = color === 'w' ? 6 : 1;
    if (r + dir >= 0 && r + dir <= 7 && !board[r + dir][c]) {
      moves.push([r + dir, c]);
      if (r === startRow && !board[r + 2 * dir][c]) moves.push([r + 2 * dir, c]);
    }
    for (const dc of [-1, 1]) {
      const nr = r + dir, nc = c + dc;
      if (nr >= 0 && nr <= 7 && nc >= 0 && nc <= 7) {
        const t = board[nr][nc];
        if (t && t[0] === enemy) moves.push([nr, nc]);
      }
    }
  } else if (type === 'r') slide([[1,0],[-1,0],[0,1],[0,-1]]);
  else if (type === 'n') {
    for (const [dr, dc] of [[2,1],[2,-1],[-2,1],[-2,-1],[1,2],[1,-2],[-1,2],[-1,-2]]) {
      const nr = r + dr, nc = c + dc;
      if (nr >= 0 && nr <= 7 && nc >= 0 && nc <= 7) {
        const t = board[nr][nc];
        if (!t || t[0] === enemy) moves.push([nr, nc]);
      }
    }
  } else if (type === 'b') slide([[1,1],[1,-1],[-1,1],[-1,-1]]);
  else if (type === 'q') slide([[1,0],[-1,0],[0,1],[0,-1],[1,1],[1,-1],[-1,1],[-1,-1]]);
  else if (type === 'k') {
    for (const [dr, dc] of [[1,0],[-1,0],[0,1],[0,-1],[1,1],[1,-1],[-1,1],[-1,-1]]) {
      const nr = r + dr, nc = c + dc;
      if (nr >= 0 && nr <= 7 && nc >= 0 && nc <= 7) {
        const t = board[nr][nc];
        if (!t || t[0] === enemy) moves.push([nr, nc]);
      }
    }
  }
  return moves;
}

function applyChessMove(room, move) {
  const { from, to } = move;
  const board = room.state.board;
  const piece = board[from[0]][from[1]];
  if (!piece || piece[0] !== room.state.turn) return false;
  const valid = getChessMoves(board, from[0], from[1]);
  if (!valid.some(([r, c]) => r === to[0] && c === to[1])) return false;

  board[to[0]][to[1]] = piece;
  board[from[0]][from[1]] = null;
  if (piece === 'wp' && to[0] === 0) board[to[0]][to[1]] = 'wq';
  if (piece === 'bp' && to[0] === 7) board[to[0]][to[1]] = 'bq';
  room.state.turn = room.state.turn === 'w' ? 'b' : 'w';
  return true;
}

function chessEvaluate(board) {
  const values = { p: 100, n: 320, b: 330, r: 500, q: 900, k: 20000 };
  let score = 0;
  for (let r = 0; r < 8; r++) {
    for (let c = 0; c < 8; c++) {
      const p = board[r][c];
      if (!p) continue;
      const v = values[p[1]] || 0;
      score += p[0] === 'b' ? v : -v;
    }
  }
  return score;
}

function chessMinimax(board, depth, alpha, beta, isMax) {
  if (depth === 0) return chessEvaluate(board);
  const color = isMax ? 'b' : 'w';
  let best = isMax ? -Infinity : Infinity;

  for (let r = 0; r < 8; r++) {
    for (let c = 0; c < 8; c++) {
      const p = board[r][c];
      if (!p || p[0] !== color) continue;
      const moves = getChessMoves(board, r, c);
      for (const [nr, nc] of moves) {
        const captured = board[nr][nc];
        board[nr][nc] = p;
        board[r][c] = null;
        const score = chessMinimax(board, depth - 1, alpha, beta, !isMax);
        board[r][c] = p;
        board[nr][nc] = captured;
        if (isMax) { best = Math.max(best, score); alpha = Math.max(alpha, score); }
        else { best = Math.min(best, score); beta = Math.min(beta, score); }
        if (beta <= alpha) return best;
      }
    }
  }
  return best;
}

function aiChess(room) {
  const board = room.state.board;
  let bestScore = -Infinity, bestMove = null;
  for (let r = 0; r < 8; r++) {
    for (let c = 0; c < 8; c++) {
      const p = board[r][c];
      if (!p || p[0] !== 'b') continue;
      const moves = getChessMoves(board, r, c);
      for (const [nr, nc] of moves) {
        const captured = board[nr][nc];
        board[nr][nc] = p;
        board[r][c] = null;
        const score = chessMinimax(board, 2, -Infinity, Infinity, false);
        board[r][c] = p;
        board[nr][nc] = captured;
        if (score > bestScore) { bestScore = score; bestMove = { from: [r, c], to: [nr, nc] }; }
      }
    }
  }
  if (bestMove) applyChessMove(room, bestMove);
}

// ===== LUDO =====
function initLudoState() {
  return {
    players: [
      { color: 'red', pieces: [-1,-1,-1,-1], finish: 0 },
      { color: 'blue', pieces: [-1,-1,-1,-1], finish: 0 },
      { color: 'green', pieces: [-1,-1,-1,-1], finish: 0 },
      { color: 'yellow', pieces: [-1,-1,-1,-1], finish: 0 }
    ],
    currentPlayer: 0, dice: null, rolled: false
  };
}

function applyLudoMove(room, move) {
  const s = room.state;
  if (move._rollOnly) {
    if (s.rolled) return false;
    s.dice = move.dice || Math.floor(Math.random() * 6) + 1;
    s.rolled = true;
    return true;
  }
  if (!s.rolled || !s.dice) return false;
  const pieceIdx = move.pieceIdx;
  if (pieceIdx === undefined || pieceIdx < 0 || pieceIdx > 3) return false;

  const player = s.players[s.currentPlayer];
  const curr = player.pieces[pieceIdx];

  if (s.dice === 6 && curr === -1) {
    player.pieces[pieceIdx] = 0;
  } else if (curr >= 0 && curr < 56) {
    player.pieces[pieceIdx] = Math.min(curr + s.dice, 56);
    if (player.pieces[pieceIdx] >= 56) { player.pieces[pieceIdx] = 99; player.finish++; }
  } else return false;

  s.rolled = false;
  s.dice = null;
  let next = (s.currentPlayer + 1) % 4;
  let attempts = 0;
  while (s.players[next].finish >= 4 && attempts < 4) { next = (next + 1) % 4; attempts++; }
  s.currentPlayer = next;
  return true;
}

function aiLudo(room) {
  const s = room.state;
  s.dice = Math.floor(Math.random() * 6) + 1;
  s.rolled = true;
  setTimeout(() => {
    const player = s.players[s.currentPlayer];
    const validPieces = player.pieces.map((p, i) => ({ p, i })).filter(({ p }) => p === -1 || (p >= 0 && p < 56));
    if (validPieces.length) {
      const pick = validPieces[Math.floor(Math.random() * validPieces.length)];
      applyLudoMove(room, { pieceIdx: pick.i });
    } else {
      s.rolled = false; s.dice = null;
      let next = (s.currentPlayer + 1) % 4;
      let attempts = 0;
      while (s.players[next].finish >= 4 && attempts < 4) { next = (next + 1) % 4; attempts++; }
      s.currentPlayer = next;
    }
  }, 800);
}

// ===== TIC TAC TOE =====
function initTicTacToe() {
  return { board: Array(9).fill(null), currentPlayer: 'X', winner: null, winningLine: null };
}

function applyTicTacToeMove(room, move) {
  const s = room.state;
  const { index } = move;
  if (s.board[index] || s.winner) return false;
  s.board[index] = s.currentPlayer;

  const lines = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  for (const line of lines) {
    const [a,b,c] = line;
    if (s.board[a] && s.board[a] === s.board[b] && s.board[a] === s.board[c]) {
      s.winner = s.board[a];
      s.winningLine = line;
      return true;
    }
  }
  if (s.board.every(c => c)) { s.winner = 'draw'; return true; }
  s.currentPlayer = s.currentPlayer === 'X' ? 'O' : 'X';
  return true;
}

function checkWin(board, player) {
  const lines = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  return lines.some(([a,b,c]) => board[a] === player && board[b] === player && board[c] === player);
}

function aiTicTacToe(room) {
  const s = room.state;
  if (s.winner || s.currentPlayer !== 'O') return;
  const empty = s.board.map((v, i) => v ? null : i).filter(v => v !== null);
  if (!empty.length) return;

  for (const i of empty) {
    const test = [...s.board]; test[i] = 'O';
    if (checkWin(test, 'O')) { applyTicTacToeMove(room, { index: i }); return; }
  }
  for (const i of empty) {
    const test = [...s.board]; test[i] = 'X';
    if (checkWin(test, 'X')) { applyTicTacToeMove(room, { index: i }); return; }
  }
  if (!s.board[4]) { applyTicTacToeMove(room, { index: 4 }); return; }
  const pick = empty[Math.floor(Math.random() * empty.length)];
  applyTicTacToeMove(room, { index: pick });
}

// ============================================================
// SOCKET
// ============================================================
io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('Login diperlukan'));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    await db.read();
    const user = db.data.users.find(u => u.id === decoded.id);
    if (!user) return next(new Error('User tidak ditemukan'));
    socket.user = { id: user.id, username: user.username, avatar: user.avatar };
    next();
  } catch (err) { next(new Error('Token tidak valid')); }
});

io.on('connection', (socket) => {
  console.log('🔌 Connected:', socket.user.username);
  io.emit('online-count', io.engine.clientsCount);

  socket.on('send-message', async (data) => {
    const msg = {
      id: uuidv4(), type: 'user',
      userId: socket.user.id, username: socket.user.username, avatar: socket.user.avatar,
      message: String(data.message || '').slice(0, 500),
      createdAt: new Date().toISOString()
    };
    await db.read();
    db.data.chats.push(msg);
    if (db.data.chats.length > 500) db.data.chats = db.data.chats.slice(-500);
    await db.write();
    io.emit('chat-message', msg);
  });

  socket.on('game:list', ({ game }, callback) => callback(getRoomList(game)));

  socket.on('game:create', ({ game }, callback) => {
    const roomId = generateRoomId();
    let state, maxPlayers = 2;

    if (game === 'chess') { state = { board: initChessBoard(), turn: 'w' }; maxPlayers = 2; }
    else if (game === 'ludo') { state = initLudoState(); maxPlayers = 4; }
    else if (game === 'tictactoe') { state = initTicTacToe(); maxPlayers = 2; }
    else return callback({ error: 'Game tidak dikenal' });

    gameRooms.set(roomId, {
      game, players: [socket.id], hostName: socket.user.username, state,
      maxPlayers, aiMode: false, createdAt: new Date().toISOString()
    });
    socket.join('game-' + roomId);
    socket.currentRoom = roomId;
    callback({ roomId, state, role: 'host', maxPlayers });
  });

  socket.on('game:join', ({ roomId }, callback) => {
    const room = gameRooms.get(roomId);
    if (!room) return callback({ error: 'Room tidak ditemukan' });
    if (room.players.length >= room.maxPlayers) return callback({ error: 'Room penuh' });

    room.players.push(socket.id);
    socket.join('game-' + roomId);
    socket.currentRoom = roomId;

    io.to('game-' + roomId).emit('game:start', { state: room.state });
    callback({ roomId, state: room.state, role: 'guest' });
  });

  socket.on('game:vs-ai', ({ game }, callback) => {
    const roomId = generateRoomId();
    let state;
    if (game === 'chess') state = { board: initChessBoard(), turn: 'w' };
    else if (game === 'ludo') state = initLudoState();
    else if (game === 'tictactoe') state = initTicTacToe();
    else return callback({ error: 'Game tidak dikenal' });

    gameRooms.set(roomId, {
      game, players: [socket.id], hostName: socket.user.username, state,
      maxPlayers: 2, aiMode: true, createdAt: new Date().toISOString()
    });
    socket.join('game-' + roomId);
    socket.currentRoom = roomId;
    callback({ roomId, state, role: 'host', aiMode: true });
  });

  socket.on('game:move', ({ roomId, move }, callback) => {
    const room = gameRooms.get(roomId);
    if (!room) return callback?.({ error: 'Room tidak ditemukan' });

    let ok = false;
    if (room.game === 'chess') ok = applyChessMove(room, move);
    else if (room.game === 'ludo') ok = applyLudoMove(room, move);
    else if (room.game === 'tictactoe') ok = applyTicTacToeMove(room, move);

    io.to('game-' + roomId).emit('game:update', { state: room.state });

    if (room.aiMode) {
      const isAIturn =
        (room.game === 'chess' && room.state.turn === 'b') ||
        (room.game === 'tictactoe' && room.state.currentPlayer === 'O') ||
        (room.game === 'ludo' && room.state.currentPlayer !== 0);

      if (isAIturn) {
        setTimeout(() => {
          if (room.game === 'chess') aiChess(room);
          else if (room.game === 'tictactoe') aiTicTacToe(room);
          else if (room.game === 'ludo') aiLudo(room);
          io.to('game-' + roomId).emit('game:update', { state: room.state });
        }, 600);
      }
    }
    callback?.({ success: ok });
  });

  socket.on('game:leave', ({ roomId }) => {
    const room = gameRooms.get(roomId);
    if (!room) return;
    room.players = room.players.filter(p => p !== socket.id);
    socket.leave('game-' + roomId);
    socket.currentRoom = null;
    if (room.players.length === 0) gameRooms.delete(roomId);
    else io.to('game-' + roomId).emit('game:opponent-left');
  });

  socket.on('disconnect', () => {
    if (socket.currentRoom) {
      const room = gameRooms.get(socket.currentRoom);
      if (room) {
        room.players = room.players.filter(p => p !== socket.id);
        if (room.players.length === 0) gameRooms.delete(socket.currentRoom);
        else io.to('game-' + socket.currentRoom).emit('game:opponent-left');
      }
    }
    io.emit('online-count', io.engine.clientsCount);
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`🕷️  ZIROWR STORE`);
  console.log(`🌐 http://localhost:${PORT}`);
});