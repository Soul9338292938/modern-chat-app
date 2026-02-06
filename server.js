// ===== IMPORTS =====
require("dotenv").config();

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ===== APP SETUP =====
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

app.use(cors());
app.use(express.json());
app.use(express.static("public")); // serves login/main/store/cart pages

// ===== DATABASE =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ===== CREATE TABLE ON START =====
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
      );
    `);

    console.log("✅ Users table ready");
  } catch (err) {
    console.error("❌ DB error:", err.message);
  }
})();

// ===== SIGNUP =====
app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ error: "Missing fields" });

    if (password.length < 4)
      return res.status(400).json({ error: "Password too short" });

    const hash = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      [username, hash]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Signup error:", err.message);
    res.status(500).json({ error: "Signup failed" });
  }
});

// ===== LOGIN =====
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (result.rows.length === 0)
      return res.status(400).json({ error: "User not found" });

    const user = result.rows[0];

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ error: "Wrong password" });

    const token = jwt.sign(
      { id: user.id, username: user.username },
      "secret_key",
      { expiresIn: "7d" }
    );

    res.json({ success: true, token, username: user.username });
  } catch (err) {
    console.error("Login error:", err.message);
    res.status(500).json({ error: "Login failed" });
  }
});

// ===== SOCKET.IO CHAT (next feature ready) =====
io.on("connection", socket => {
  console.log("🔌 User connected");

  socket.on("chat message", msg => {
    io.emit("chat message", msg); // broadcast to everyone
  });

  socket.on("disconnect", () => {
    console.log("❌ User disconnected");
  });
});

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log("🚀 Server running on port " + PORT);
});
