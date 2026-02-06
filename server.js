const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

/* ===== DATABASE ===== */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ===== CREATE USERS TABLE ===== */
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
})();

/* ===== AUTH HELPERS ===== */
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.sendStatus(401);

  const token = header.split(" ")[1];

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.sendStatus(403);
  }
}

/* ===== SIGNUP ===== */
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.json({ error: "Missing fields" });

  const hash = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      "INSERT INTO users(username,password) VALUES($1,$2)",
      [username, hash]
    );
    res.json({ success: true });
  } catch {
    res.json({ error: "Username already exists" });
  }
});

/* ===== LOGIN ===== */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    "SELECT * FROM users WHERE username=$1",
    [username]
  );

  if (!result.rows.length)
    return res.json({ error: "Invalid credentials" });

  const user = result.rows[0];
  const ok = await bcrypt.compare(password, user.password);

  if (!ok) return res.json({ error: "Invalid credentials" });

  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token });
});

/* ===== CURRENT USER ===== */
app.get("/me", auth, (req, res) => {
  res.json(req.user);
});

/* ===== START ===== */
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server running on " + PORT));
