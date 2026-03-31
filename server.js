<meta name='viewport' content='width=device-width, initial-scale=1'/>// server.js
// Hybrid NAS backend - Fastify + SQLite + encrypted local storage
// Port: process.env.PORT || 1108
// Storage path: ./storage

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Fastify = require('fastify');
const fastifyMultipart = require('@fastify/multipart');
const fastifyJwt = require('@fastify/jwt');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// ----------------------
// Config
// ----------------------
const PORT = process.env.PORT || 1108;
const STORAGE_DIR = path.join(__dirname, 'storage');
const DB_PATH = path.join(__dirname, 'nas.db');
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';
const MASTER_KEY = process.env.MASTER_KEY || crypto.randomBytes(32).toString('hex'); // AES-256 key

if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// ----------------------
// DB setup
// ----------------------
const db = new Database(DB_PATH);

db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  parent_id INTEGER,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  folder_id INTEGER,
  name TEXT NOT NULL,
  size INTEGER NOT NULL,
  mime_type TEXT,
  storage_path TEXT NOT NULL,
  is_private INTEGER NOT NULL DEFAULT 0,
  ipfs_cid TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  UNIQUE(user_id, name),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_tags (
  file_id INTEGER NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY(file_id, tag_id),
  FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
  FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
`);

// ----------------------
// Helpers
// ----------------------
function now() {
  return new Date().toISOString();
}

function logAction(userId, action, details) {
  db.prepare(
    `INSERT INTO logs (user_id, action, details, created_at)
     VALUES (?, ?, ?, ?)`
  ).run(userId || null, action, details ? JSON.stringify(details) : null, now());
}

function encryptBuffer(buffer) {
  const key = Buffer.from(MASTER_KEY, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]); // [12 IV][16 TAG][data]
}

function decryptBuffer(buffer) {
  const key = Buffer.from(MASTER_KEY, 'hex');
  const iv = buffer.slice(0, 12);
  const tag = buffer.slice(12, 28);
  const data = buffer.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ----------------------
// Fastify setup
// ----------------------
const fastify = Fastify({
  logger: true
});

fastify.register(fastifyMultipart);
fastify.register(fastifyJwt, { secret: JWT_SECRET });

// Auth decorator
fastify.decorate("authenticate", async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.code(401).send({ error: 'Unauthorized' });
  }
});

// ----------------------
// Auth routes
// ----------------------

// Register
fastify.post('/auth/register', async (request, reply) => {
  const { username, password, adminSecret } = request.body || {};
  if (!username || !password) {
    return reply.code(400).send({ error: 'username and password required' });
  }

  const isAdmin = adminSecret && adminSecret === (process.env.ADMIN_SECRET || 'make-me-admin') ? 1 : 0;

  const hash = await bcrypt.hash(password, 10);
  try {
    const stmt = db.prepare(
      `INSERT INTO users (username, password_hash, is_admin, created_at)
       VALUES (?, ?, ?, ?)`
    );
    const info = stmt.run(username, hash, isAdmin, now());
    logAction(info.lastInsertRowid, 'register', { username, is_admin: !!isAdmin });
    return { success: true };
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return reply.code(400).send({ error: 'username already exists' });
    }
    request.log.error(e);
    return reply.code(500).send({ error: 'internal error' });
  }
});

// Login
fastify.post('/auth/login', async (request, reply) => {
  const { username, password } = request.body || {};
  if (!username || !password) {
    return reply.code(400).send({ error: 'username and password required' });
  }

  const user = db.prepare(
    `SELECT * FROM users WHERE username = ?`
  ).get(username);

  if (!user) {
    return reply.code(401).send({ error: 'invalid credentials' });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return reply.code(401).send({ error: 'invalid credentials' });
  }

  const token = fastify.jwt.sign({
    userId: user.id,
    username: user.username,
    isAdmin: !!user.is_admin
  }, { expiresIn: '7d' });

  logAction(user.id, 'login', null);
  return { token };
});

// Me
fastify.get('/me', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId } = request.user;
  const user = db.prepare(
    `SELECT id, username, is_admin, created_at FROM users WHERE id = ?`
  ).get(userId);
  if (!user) return reply.code(404).send({ error: 'user not found' });
  return { user };
});

// ----------------------
// Folder routes
// ----------------------
fastify.post('/folders', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId } = request.user;
  const { name, parentId } = request.body || {};
  if (!name) return reply.code(400).send({ error: 'name required' });

  const stmt = db.prepare(
    `INSERT INTO folders (user_id, name, parent_id, created_at)
     VALUES (?, ?, ?, ?)`
  );
  const info = stmt.run(userId, name, parentId || null, now());
  logAction(userId, 'create_folder', { name, parentId: parentId || null });
  return { id: info.lastInsertRowid, name, parentId: parentId || null };
});

fastify.get('/folders', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  let rows;
  if (isAdmin) {
    rows = db.prepare(
      `SELECT * FROM folders`
    ).all();
  } else {
    rows = db.prepare(
      `SELECT * FROM folders WHERE user_id = ?`
    ).all(userId);
  }
  return { folders: rows };
});

// ----------------------
// Tag routes
// ----------------------
fastify.post('/tags', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId } = request.user;
  const { name } = request.body || {};
  if (!name) return reply.code(400).send({ error: 'name required' });

  try {
    const stmt = db.prepare(
      `INSERT INTO tags (user_id, name) VALUES (?, ?)`
    );
    const info = stmt.run(userId, name);
    logAction(userId, 'create_tag', { name });
    return { id: info.lastInsertRowid, name };
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      const existing = db.prepare(
        `SELECT * FROM tags WHERE user_id = ? AND name = ?`
      ).get(userId, name);
      return { id: existing.id, name: existing.name };
    }
    request.log.error(e);
    return reply.code(500).send({ error: 'internal error' });
  }
});

fastify.get('/tags', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  let rows;
  if (isAdmin) {
    rows = db.prepare(`SELECT * FROM tags`).all();
  } else {
    rows = db.prepare(`SELECT * FROM tags WHERE user_id = ?`).all(userId);
  }
  return { tags: rows };
});

// ----------------------
// File upload
// ----------------------
fastify.post('/files/upload', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { userId } = request.user;

  const parts = request.parts();
  let folderId = null;
  let tags = [];
  let isPrivate = 0;

  let filePart = null;

  for await (const part of parts) {
    if (part.type === 'file') {
      filePart = part;
    } else {
      if (part.fieldname === 'folderId') {
        folderId = part.value ? parseInt(part.value, 10) : null;
      } else if (part.fieldname === 'tags') {
        try {
          tags = JSON.parse(part.value || '[]');
        } catch {
          tags = [];
        }
      } else if (part.fieldname === 'isPrivate') {
        isPrivate = part.value === 'true' ? 1 : 0;
      }
    }
  }

  if (!filePart) {
    return reply.code(400).send({ error: 'file required' });
  }

  const fileId = uuidv4();
  const filename = filePart.filename || 'file';
  const mimeType = filePart.mimetype || 'application/octet-stream';
  const chunks = [];
  let size = 0;

  for await (const chunk of filePart.file) {
    chunks.push(chunk);
    size += chunk.length;
  }

  const buffer = Buffer.concat(chunks);
  const encrypted = encryptBuffer(buffer);

  const userDir = path.join(STORAGE_DIR, String(userId));
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

  const storagePath = path.join(userDir, fileId + '.bin');
  fs.writeFileSync(storagePath, encrypted);

  const stmt = db.prepare(
    `INSERT INTO files (user_id, folder_id, name, size, mime_type, storage_path, is_private, ipfs_cid, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const info = stmt.run(
    userId,
    folderId || null,
    filename,
    size,
    mimeType,
    storagePath,
    isPrivate,
    null,
    now()
  );

  const fileDbId = info.lastInsertRowid;

  // Tags
  for (const t of tags) {
    if (!t || typeof t !== 'string') continue;
    let tagRow = db.prepare(
      `SELECT * FROM tags WHERE user_id = ? AND name = ?`
    ).get(userId, t);
    if (!tagRow) {
      const tagInfo = db.prepare(
        `INSERT INTO tags (user_id, name) VALUES (?, ?)`
      ).run(userId, t);
      tagRow = { id: tagInfo.lastInsertRowid, name: t };
    }
    db.prepare(
      `INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)`
    ).run(fileDbId, tagRow.id);
  }

  logAction(userId, 'upload_file', { filename, size, folderId, isPrivate: !!isPrivate });

  return {
    id: fileDbId,
    name: filename,
    size,
    mimeType,
    isPrivate: !!isPrivate
  };
});

// ----------------------
// List files
// ----------------------
fastify.get('/files', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  const { folderId, tag } = request.query || {};

  let rows;
  if (tag) {
    // Filter by tag
    const sql = `
      SELECT f.*
      FROM files f
      JOIN file_tags ft ON ft.file_id = f.id
      JOIN tags t ON t.id = ft.tag_id
      WHERE (${isAdmin ? '1=1' : 'f.user_id = ?'}) AND t.name = ?
      ${folderId ? 'AND f.folder_id = ?' : ''}
      ORDER BY f.created_at DESC
    `;
    const params = [];
    if (!isAdmin) params.push(userId);
    params.push(tag);
    if (folderId) params.push(folderId);
    rows = db.prepare(sql).all(...params);
  } else {
    const sql = `
      SELECT * FROM files
      WHERE ${isAdmin ? '1=1' : 'user_id = ?'}
      ${folderId ? 'AND folder_id = ?' : ''}
      ORDER BY created_at DESC
    `;
    const params = [];
    if (!isAdmin) params.push(userId);
    if (folderId) params.push(folderId);
    rows = db.prepare(sql).all(...params);
  }

  // Attach tags
  const tagStmt = db.prepare(`
    SELECT t.name
    FROM tags t
    JOIN file_tags ft ON ft.tag_id = t.id
    WHERE ft.file_id = ?
  `);

  const files = rows.map(r => {
    const tags = tagStmt.all(r.id).map(x => x.name);
    return {
      id: r.id,
      name: r.name,
      size: r.size,
      mimeType: r.mime_type,
      folderId: r.folder_id,
      isPrivate: !!r.is_private,
      ipfsCid: r.ipfs_cid,
      createdAt: r.created_at,
      tags
    };
  });

  return { files };
});

// ----------------------
// Download file
// ----------------------
fastify.get('/files/:id/download', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  const id = parseInt(request.params.id, 10);
  const file = db.prepare(
    `SELECT * FROM files WHERE id = ?`
  ).get(id);

  if (!file) return reply.code(404).send({ error: 'file not found' });
  if (!isAdmin && file.user_id !== userId) {
    return reply.code(403).send({ error: 'forbidden' });
  }

  if (!fs.existsSync(file.storage_path)) {
    return reply.code(410).send({ error: 'file missing from storage' });
  }

  const encrypted = fs.readFileSync(file.storage_path);
  const decrypted = decryptBuffer(encrypted);

  logAction(userId, 'download_file', { fileId: id, name: file.name });

  reply.header('Content-Type', file.mime_type || 'application/octet-stream');
  reply.header('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
  return reply.send(decrypted);
});

// ----------------------
// Delete file
// ----------------------
fastify.delete('/files/:id', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  const id = parseInt(request.params.id, 10);
  const file = db.prepare(
    `SELECT * FROM files WHERE id = ?`
  ).get(id);

  if (!file) return reply.code(404).send({ error: 'file not found' });
  if (!isAdmin && file.user_id !== userId) {
    return reply.code(403).send({ error: 'forbidden' });
  }

  if (fs.existsSync(file.storage_path)) {
    fs.unlinkSync(file.storage_path);
  }

  db.prepare(`DELETE FROM files WHERE id = ?`).run(id);
  logAction(userId, 'delete_file', { fileId: id, name: file.name });

  return { success: true };
});

// ----------------------
// Simple index backup (metadata only, no IPFS here)
// ----------------------
fastify.get('/index/backup', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;

  const users = isAdmin
    ? db.prepare(`SELECT id, username, is_admin, created_at FROM users`).all()
    : db.prepare(`SELECT id, username, is_admin, created_at FROM users WHERE id = ?`).all(userId);

  const folders = isAdmin
    ? db.prepare(`SELECT * FROM folders`).all()
    : db.prepare(`SELECT * FROM folders WHERE user_id = ?`).all(userId);

  const files = isAdmin
    ? db.prepare(`SELECT * FROM files`).all()
    : db.prepare(`SELECT * FROM files WHERE user_id = ?`).all(userId);

  const tags = isAdmin
    ? db.prepare(`SELECT * FROM tags`).all()
    : db.prepare(`SELECT * FROM tags WHERE user_id = ?`).all(userId);

  const fileTags = isAdmin
    ? db.prepare(`SELECT * FROM file_tags`).all()
    : db.prepare(`
        SELECT ft.*
        FROM file_tags ft
        JOIN files f ON f.id = ft.file_id
        WHERE f.user_id = ?
      `).all(userId);

  const payload = { users, folders, files, tags, fileTags };
  logAction(userId, 'backup_index', { scope: isAdmin ? 'all' : 'self' });
  return payload;
});

// ----------------------
// Start server
// ----------------------
const start = async () => {
  try {
    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    fastify.log.info(`NAS backend running on port ${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
<script>// server.js
// Hybrid NAS backend - Fastify + SQLite + encrypted local storage
// Port: process.env.PORT || 1108
// Storage path: ./storage

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Fastify = require('fastify');
const fastifyMultipart = require('@fastify/multipart');
const fastifyJwt = require('@fastify/jwt');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

// ----------------------
// Config
// ----------------------
const PORT = process.env.PORT || 1108;
const STORAGE_DIR = path.join(__dirname, 'storage');
const DB_PATH = path.join(__dirname, 'nas.db');
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';
const MASTER_KEY = process.env.MASTER_KEY || crypto.randomBytes(32).toString('hex'); // AES-256 key

if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// ----------------------
// DB setup
// ----------------------
const db = new Database(DB_PATH);

db.exec(`
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS folders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  parent_id INTEGER,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(parent_id) REFERENCES folders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  folder_id INTEGER,
  name TEXT NOT NULL,
  size INTEGER NOT NULL,
  mime_type TEXT,
  storage_path TEXT NOT NULL,
  is_private INTEGER NOT NULL DEFAULT 0,
  ipfs_cid TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  UNIQUE(user_id, name),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_tags (
  file_id INTEGER NOT NULL,
  tag_id INTEGER NOT NULL,
  PRIMARY KEY(file_id, tag_id),
  FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE,
  FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  details TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
);
`);

// ----------------------
// Helpers
// ----------------------
function now() {
  return new Date().toISOString();
}

function logAction(userId, action, details) {
  db.prepare(
    `INSERT INTO logs (user_id, action, details, created_at)
     VALUES (?, ?, ?, ?)`
  ).run(userId || null, action, details ? JSON.stringify(details) : null, now());
}

function encryptBuffer(buffer) {
  const key = Buffer.from(MASTER_KEY, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]); // [12 IV][16 TAG][data]
}

function decryptBuffer(buffer) {
  const key = Buffer.from(MASTER_KEY, 'hex');
  const iv = buffer.slice(0, 12);
  const tag = buffer.slice(12, 28);
  const data = buffer.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

// ----------------------
// Fastify setup
// ----------------------
const fastify = Fastify({
  logger: true
});

fastify.register(fastifyMultipart);
fastify.register(fastifyJwt, { secret: JWT_SECRET });

// Auth decorator
fastify.decorate("authenticate", async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.code(401).send({ error: 'Unauthorized' });
  }
});

// ----------------------
// Auth routes
// ----------------------

// Register
fastify.post('/auth/register', async (request, reply) => {
  const { username, password, adminSecret } = request.body || {};
  if (!username || !password) {
    return reply.code(400).send({ error: 'username and password required' });
  }

  const isAdmin = adminSecret && adminSecret === (process.env.ADMIN_SECRET || 'make-me-admin') ? 1 : 0;

  const hash = await bcrypt.hash(password, 10);
  try {
    const stmt = db.prepare(
      `INSERT INTO users (username, password_hash, is_admin, created_at)
       VALUES (?, ?, ?, ?)`
    );
    const info = stmt.run(username, hash, isAdmin, now());
    logAction(info.lastInsertRowid, 'register', { username, is_admin: !!isAdmin });
    return { success: true };
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return reply.code(400).send({ error: 'username already exists' });
    }
    request.log.error(e);
    return reply.code(500).send({ error: 'internal error' });
  }
});

// Login
fastify.post('/auth/login', async (request, reply) => {
  const { username, password } = request.body || {};
  if (!username || !password) {
    return reply.code(400).send({ error: 'username and password required' });
  }

  const user = db.prepare(
    `SELECT * FROM users WHERE username = ?`
  ).get(username);

  if (!user) {
    return reply.code(401).send({ error: 'invalid credentials' });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return reply.code(401).send({ error: 'invalid credentials' });
  }

  const token = fastify.jwt.sign({
    userId: user.id,
    username: user.username,
    isAdmin: !!user.is_admin
  }, { expiresIn: '7d' });

  logAction(user.id, 'login', null);
  return { token };
});

// Me
fastify.get('/me', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId } = request.user;
  const user = db.prepare(
    `SELECT id, username, is_admin, created_at FROM users WHERE id = ?`
  ).get(userId);
  if (!user) return reply.code(404).send({ error: 'user not found' });
  return { user };
});

// ----------------------
// Folder routes
// ----------------------
fastify.post('/folders', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId } = request.user;
  const { name, parentId } = request.body || {};
  if (!name) return reply.code(400).send({ error: 'name required' });

  const stmt = db.prepare(
    `INSERT INTO folders (user_id, name, parent_id, created_at)
     VALUES (?, ?, ?, ?)`
  );
  const info = stmt.run(userId, name, parentId || null, now());
  logAction(userId, 'create_folder', { name, parentId: parentId || null });
  return { id: info.lastInsertRowid, name, parentId: parentId || null };
});

fastify.get('/folders', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  let rows;
  if (isAdmin) {
    rows = db.prepare(
      `SELECT * FROM folders`
    ).all();
  } else {
    rows = db.prepare(
      `SELECT * FROM folders WHERE user_id = ?`
    ).all(userId);
  }
  return { folders: rows };
});

// ----------------------
// Tag routes
// ----------------------
fastify.post('/tags', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId } = request.user;
  const { name } = request.body || {};
  if (!name) return reply.code(400).send({ error: 'name required' });

  try {
    const stmt = db.prepare(
      `INSERT INTO tags (user_id, name) VALUES (?, ?)`
    );
    const info = stmt.run(userId, name);
    logAction(userId, 'create_tag', { name });
    return { id: info.lastInsertRowid, name };
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      const existing = db.prepare(
        `SELECT * FROM tags WHERE user_id = ? AND name = ?`
      ).get(userId, name);
      return { id: existing.id, name: existing.name };
    }
    request.log.error(e);
    return reply.code(500).send({ error: 'internal error' });
  }
});

fastify.get('/tags', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  let rows;
  if (isAdmin) {
    rows = db.prepare(`SELECT * FROM tags`).all();
  } else {
    rows = db.prepare(`SELECT * FROM tags WHERE user_id = ?`).all(userId);
  }
  return { tags: rows };
});

// ----------------------
// File upload
// ----------------------
fastify.post('/files/upload', {
  preHandler: [fastify.authenticate]
}, async (request, reply) => {
  const { userId } = request.user;

  const parts = request.parts();
  let folderId = null;
  let tags = [];
  let isPrivate = 0;

  let filePart = null;

  for await (const part of parts) {
    if (part.type === 'file') {
      filePart = part;
    } else {
      if (part.fieldname === 'folderId') {
        folderId = part.value ? parseInt(part.value, 10) : null;
      } else if (part.fieldname === 'tags') {
        try {
          tags = JSON.parse(part.value || '[]');
        } catch {
          tags = [];
        }
      } else if (part.fieldname === 'isPrivate') {
        isPrivate = part.value === 'true' ? 1 : 0;
      }
    }
  }

  if (!filePart) {
    return reply.code(400).send({ error: 'file required' });
  }

  const fileId = uuidv4();
  const filename = filePart.filename || 'file';
  const mimeType = filePart.mimetype || 'application/octet-stream';
  const chunks = [];
  let size = 0;

  for await (const chunk of filePart.file) {
    chunks.push(chunk);
    size += chunk.length;
  }

  const buffer = Buffer.concat(chunks);
  const encrypted = encryptBuffer(buffer);

  const userDir = path.join(STORAGE_DIR, String(userId));
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

  const storagePath = path.join(userDir, fileId + '.bin');
  fs.writeFileSync(storagePath, encrypted);

  const stmt = db.prepare(
    `INSERT INTO files (user_id, folder_id, name, size, mime_type, storage_path, is_private, ipfs_cid, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const info = stmt.run(
    userId,
    folderId || null,
    filename,
    size,
    mimeType,
    storagePath,
    isPrivate,
    null,
    now()
  );

  const fileDbId = info.lastInsertRowid;

  // Tags
  for (const t of tags) {
    if (!t || typeof t !== 'string') continue;
    let tagRow = db.prepare(
      `SELECT * FROM tags WHERE user_id = ? AND name = ?`
    ).get(userId, t);
    if (!tagRow) {
      const tagInfo = db.prepare(
        `INSERT INTO tags (user_id, name) VALUES (?, ?)`
      ).run(userId, t);
      tagRow = { id: tagInfo.lastInsertRowid, name: t };
    }
    db.prepare(
      `INSERT OR IGNORE INTO file_tags (file_id, tag_id) VALUES (?, ?)`
    ).run(fileDbId, tagRow.id);
  }

  logAction(userId, 'upload_file', { filename, size, folderId, isPrivate: !!isPrivate });

  return {
    id: fileDbId,
    name: filename,
    size,
    mimeType,
    isPrivate: !!isPrivate
  };
});

// ----------------------
// List files
// ----------------------
fastify.get('/files', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  const { folderId, tag } = request.query || {};

  let rows;
  if (tag) {
    // Filter by tag
    const sql = `
      SELECT f.*
      FROM files f
      JOIN file_tags ft ON ft.file_id = f.id
      JOIN tags t ON t.id = ft.tag_id
      WHERE (${isAdmin ? '1=1' : 'f.user_id = ?'}) AND t.name = ?
      ${folderId ? 'AND f.folder_id = ?' : ''}
      ORDER BY f.created_at DESC
    `;
    const params = [];
    if (!isAdmin) params.push(userId);
    params.push(tag);
    if (folderId) params.push(folderId);
    rows = db.prepare(sql).all(...params);
  } else {
    const sql = `
      SELECT * FROM files
      WHERE ${isAdmin ? '1=1' : 'user_id = ?'}
      ${folderId ? 'AND folder_id = ?' : ''}
      ORDER BY created_at DESC
    `;
    const params = [];
    if (!isAdmin) params.push(userId);
    if (folderId) params.push(folderId);
    rows = db.prepare(sql).all(...params);
  }

  // Attach tags
  const tagStmt = db.prepare(`
    SELECT t.name
    FROM tags t
    JOIN file_tags ft ON ft.tag_id = t.id
    WHERE ft.file_id = ?
  `);

  const files = rows.map(r => {
    const tags = tagStmt.all(r.id).map(x => x.name);
    return {
      id: r.id,
      name: r.name,
      size: r.size,
      mimeType: r.mime_type,
      folderId: r.folder_id,
      isPrivate: !!r.is_private,
      ipfsCid: r.ipfs_cid,
      createdAt: r.created_at,
      tags
    };
  });

  return { files };
});

// ----------------------
// Download file
// ----------------------
fastify.get('/files/:id/download', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  const id = parseInt(request.params.id, 10);
  const file = db.prepare(
    `SELECT * FROM files WHERE id = ?`
  ).get(id);

  if (!file) return reply.code(404).send({ error: 'file not found' });
  if (!isAdmin && file.user_id !== userId) {
    return reply.code(403).send({ error: 'forbidden' });
  }

  if (!fs.existsSync(file.storage_path)) {
    return reply.code(410).send({ error: 'file missing from storage' });
  }

  const encrypted = fs.readFileSync(file.storage_path);
  const decrypted = decryptBuffer(encrypted);

  logAction(userId, 'download_file', { fileId: id, name: file.name });

  reply.header('Content-Type', file.mime_type || 'application/octet-stream');
  reply.header('Content-Disposition', `attachment; filename="${encodeURIComponent(file.name)}"`);
  return reply.send(decrypted);
});

// ----------------------
// Delete file
// ----------------------
fastify.delete('/files/:id', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;
  const id = parseInt(request.params.id, 10);
  const file = db.prepare(
    `SELECT * FROM files WHERE id = ?`
  ).get(id);

  if (!file) return reply.code(404).send({ error: 'file not found' });
  if (!isAdmin && file.user_id !== userId) {
    return reply.code(403).send({ error: 'forbidden' });
  }

  if (fs.existsSync(file.storage_path)) {
    fs.unlinkSync(file.storage_path);
  }

  db.prepare(`DELETE FROM files WHERE id = ?`).run(id);
  logAction(userId, 'delete_file', { fileId: id, name: file.name });

  return { success: true };
});

// ----------------------
// Simple index backup (metadata only, no IPFS here)
// ----------------------
fastify.get('/index/backup', { preHandler: [fastify.authenticate] }, async (request, reply) => {
  const { userId, isAdmin } = request.user;

  const users = isAdmin
    ? db.prepare(`SELECT id, username, is_admin, created_at FROM users`).all()
    : db.prepare(`SELECT id, username, is_admin, created_at FROM users WHERE id = ?`).all(userId);

  const folders = isAdmin
    ? db.prepare(`SELECT * FROM folders`).all()
    : db.prepare(`SELECT * FROM folders WHERE user_id = ?`).all(userId);

  const files = isAdmin
    ? db.prepare(`SELECT * FROM files`).all()
    : db.prepare(`SELECT * FROM files WHERE user_id = ?`).all(userId);

  const tags = isAdmin
    ? db.prepare(`SELECT * FROM tags`).all()
    : db.prepare(`SELECT * FROM tags WHERE user_id = ?`).all(userId);

  const fileTags = isAdmin
    ? db.prepare(`SELECT * FROM file_tags`).all()
    : db.prepare(`
        SELECT ft.*
        FROM file_tags ft
        JOIN files f ON f.id = ft.file_id
        WHERE f.user_id = ?
      `).all(userId);

  const payload = { users, folders, files, tags, fileTags };
  logAction(userId, 'backup_index', { scope: isAdmin ? 'all' : 'self' });
  return payload;
});

// ----------------------
// Start server
// ----------------------
const start = async () => {
  try {
    await fastify.listen({ port: PORT, host: '0.0.0.0' });
    fastify.log.info(`NAS backend running on port ${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
</script>
