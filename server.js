// server.js — TANAS starter backend (Fastify + SQLite + Auth + File metadata)

const Fastify = require("fastify");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const fastifyJwt = require("@fastify/jwt");
const cors = require("@fastify/cors");
const formbody = require("@fastify/formbody");

// -------------------------------
// App setup
// -------------------------------
const app = Fastify({ logger: true });

app.register(cors, { origin: "*" });
app.register(formbody);

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

app.register(fastifyJwt, { secret: JWT_SECRET });

app.decorate("authenticate", async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.code(401).send({ error: "Unauthorized" });
  }
});

// -------------------------------
// Database setup
// -------------------------------
const DB_PATH = path.join(__dirname, "tanas.db");
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("Failed to open SQLite database:", err);
  } else {
    console.log("SQLite database loaded:", DB_PATH);
  }
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS folders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      parent_id INTEGER,
      FOREIGN KEY(parent_id) REFERENCES folders(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      size INTEGER NOT NULL,
      folder_id INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(folder_id) REFERENCES folders(id)
    )
  `);
});

// -------------------------------
// Auth routes
// -------------------------------
app.post("/auth/register", async (request, reply) => {
  const { username, password, isAdmin } = request.body || {};

  if (!username || !password) {
    return reply.code(400).send({ error: "Username and password are required" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)`,
    [username, passwordHash, isAdmin ? 1 : 0],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return reply.code(409).send({ error: "Username already exists" });
        }
        console.error("Error creating user:", err);
        return reply.code(500).send({ error: "Failed to create user" });
      }

      reply.send({ id: this.lastID, username, is_admin: isAdmin ? 1 : 0 });
    }
  );
});

app.post("/auth/login", async (request, reply) => {
  const { username, password } = request.body || {};

  if (!username || !password) {
    return reply.code(400).send({ error: "Username and password are required" });
  }

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err) {
        console.error("Error fetching user:", err);
        return reply.code(500).send({ error: "Failed to fetch user" });
      }

      if (!user) {
        return reply.code(401).send({ error: "Invalid credentials" });
      }

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return reply.code(401).send({ error: "Invalid credentials" });
      }

      const token = app.jwt.sign({
        id: user.id,
        username: user.username,
        is_admin: !!user.is_admin
      });

      reply.send({
        token,
        user: {
          id: user.id,
          username: user.username,
          is_admin: !!user.is_admin
        }
      });
    }
  );
});

// -------------------------------
// Folder routes (basic)
// -------------------------------
app.post("/folders", { preHandler: [app.authenticate] }, (request, reply) => {
  const { name, parent_id } = request.body || {};
  if (!name) {
    return reply.code(400).send({ error: "Folder name is required" });
  }

  db.run(
    `INSERT INTO folders (name, parent_id) VALUES (?, ?)`,
    [name, parent_id || null],
    function (err) {
      if (err) {
        console.error("Error creating folder:", err);
        return reply.code(500).send({ error: "Failed to create folder" });
      }
      reply.send({ id: this.lastID, name, parent_id: parent_id || null });
    }
  );
});

app.get("/folders", { preHandler: [app.authenticate] }, (request, reply) => {
  db.all(`SELECT * FROM folders`, [], (err, rows) => {
    if (err) {
      console.error("Error fetching folders:", err);
      return reply.code(500).send({ error: "Failed to fetch folders" });
    }
    reply.send(rows);
  });
});

// -------------------------------
// File metadata routes (no real file storage yet)
// -------------------------------
app.post("/files", { preHandler: [app.authenticate] }, (request, reply) => {
  const { name, size, folder_id } = request.body || {};
  if (!name || !size) {
    return reply
      .code(400)
      .send({ error: "File name and size are required" });
  }

  db.run(
    `INSERT INTO files (name, size, folder_id) VALUES (?, ?, ?)`,
    [name, size, folder_id || null],
    function (err) {
      if (err) {
        console.error("Error creating file record:", err);
        return reply.code(500).send({ error: "Failed to create file record" });
      }
      reply.send({
        id: this.lastID,
        name,
        size,
        folder_id: folder_id || null
      });
    }
  );
});

app.get("/files", { preHandler: [app.authenticate] }, (request, reply) => {
  db.all(`SELECT * FROM files ORDER BY created_at DESC`, [], (err, rows) => {
    if (err) {
      console.error("Error fetching files:", err);
      return reply.code(500).send({ error: "Failed to fetch files" });
    }
    reply.send(rows);
  });
});

// -------------------------------
// Health check
// -------------------------------
app.get("/", async () => {
  return { status: "ok", service: "TANAS Starter Backend" };
});

// -------------------------------
// Start server
// -------------------------------
const PORT = process.env.PORT || 3000;

app
  .listen({ port: PORT, host: "0.0.0.0" })
  .then(() => console.log(`TANAS backend running on port ${PORT}`))
  .catch((err) => {
    console.error("Failed to start server:", err);
    process.exit(1);
  });
