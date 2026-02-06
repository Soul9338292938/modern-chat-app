const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

/* ================= DATABASE ================= */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ================= JWT SECRET ================= */

const JWT_SECRET = "super_secret_key_change_this";

/* ================= SOCKET ================= */

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

/* ================= TEST ROUTE ================= */

app.get("/", (req, res) => {
  res.send("Modern Chat Backend Running");
});

/* ================= SIGNUP ================= */

app.post("/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password)
      return res.status(400).json({ error: "Missing fields" });

    const hashed = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
      [username, hashed]
    );

    res.json({ success: true, userId: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ error: "Signup failed" });
  }
});

/* ================= LOGIN ================= */

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (result.rows.length === 0)
      return res.status(401).json({ error: "Invalid username" });

    const user = result.rows[0];

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id }, JWT_SECRET, {
      expiresIn: "7d"
    });

    res.json({ token });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

/* ================= AUTH TEST ================= */

app.get("/me", async (req, res) => {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: "No token" });

    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const result = await pool.query(
      "SELECT id, username FROM users WHERE id=$1",
      [decoded.id]
    );

    res.json(result.rows[0]);
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
});

/* ================= SOCKET CONNECTION ================= */

io.on("connection", (socket) => {
  console.log("User connected");

  socket.on("disconnect", () => {
    console.log("User disconnected");
  });
});

/* ================= START SERVER ================= */

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("Server running on port " + PORT));
