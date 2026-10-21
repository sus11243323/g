require("dotenv").config();
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const db = new Database(path.join(__dirname, "forum.sqlite"));
db.exec(`CREATE TABLE IF NOT EXISTS invites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT UNIQUE NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TEXT,
  used_by INTEGER,
  used_at TEXT
)`);
const token = crypto.randomBytes(24).toString("base64url");
const hash = crypto.createHash("sha256").update(token).digest("hex");
const hoursArg = Number(process.argv[2] || 168);
const hours = Math.max(1, Math.min(720, hoursArg));
const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString().replace("T", " ").replace("Z", "");
db.prepare("INSERT INTO invites (token_hash, created_by, expires_at) VALUES (?, ?, ?)").run(hash, process.env.ADMIN_EMAILS || "local-admin", expiresAt);
const base = (process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, "");
console.log(`Invite link (one use, expires in ${hours} hours):\n${base}/invite/${token}`);
db.close();
