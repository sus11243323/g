require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");

const required = ["SESSION_SECRET", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"];
const missing = required.filter((key) => !process.env[key]);
if (missing.length) {
  console.error("Missing .env values:", missing.join(", "));
  console.error("Copy .env.example to .env and configure Google OAuth.");
  process.exit(1);
}

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const adminEmails = new Set((process.env.ADMIN_EMAILS || "").split(",").map(x => x.trim().toLowerCase()).filter(Boolean));
const db = new Database(path.join(__dirname, "forum.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    avatar_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT UNIQUE NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    used_by INTEGER REFERENCES users(id),
    used_at TEXT
  );
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 5000),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);
const postColumns = db.prepare("PRAGMA table_info(posts)").all().map(column => column.name);
if (!postColumns.includes("category")) db.exec("ALTER TABLE posts ADD COLUMN category TEXT NOT NULL DEFAULT 'General'");
db.exec(`
  CREATE TABLE IF NOT EXISTS post_likes (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, post_id)
  );
`);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use(rateLimit({ windowMs: 60_000, limit: 120, standardHeaders: true, legacyHeaders: false }));
app.set("trust proxy", 1);
app.use(session({
  name: "private_forum_session",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.COOKIE_SECURE === "true",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  try { done(null, db.prepare("SELECT id, email, display_name, avatar_url FROM users WHERE id = ?").get(id) || false); }
  catch (err) { done(err); }
});
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  try {
    const emailEntry = (profile.emails || []).find(e => e.verified !== false);
    const email = emailEntry && emailEntry.value ? emailEntry.value.toLowerCase() : null;
    if (!email) return done(null, false, { message: "Google did not provide a verified email." });

    // The invitation is checked again after OAuth; no account is created before that check.
    const existing = db.prepare("SELECT * FROM users WHERE google_id = ? OR email = ?").get(profile.id, email);
    if (existing) return done(null, { ...existing, _existing: true });

    return done(null, {
      _newGoogleUser: true,
      google_id: profile.id,
      email,
      display_name: profile.displayName || email.split("@")[0],
      avatar_url: profile.photos && profile.photos[0] ? profile.photos[0].value : null
    });
  } catch (err) { return done(err); }
}));

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function currentInvite(token) {
  if (!token || typeof token !== "string") return null;
  return db.prepare(`
    SELECT * FROM invites
    WHERE token_hash = ? AND used_by IS NULL
      AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
  `).get(hashToken(token)) || null;
}
function requireLogin(req, res, next) {
  if (!req.isAuthenticated || !req.isAuthenticated()) return res.redirect("/");
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || !adminEmails.has(String(req.user.email).toLowerCase())) return res.status(403).send("Admins only.");
  next();
}
app.use((req, res, next) => {
  res.locals.user = req.user || null;
  res.locals.isAdmin = !!(req.user && adminEmails.has(String(req.user.email).toLowerCase()));
  next();
});

app.get("/", (req, res) => {
  if (req.user) return res.redirect("/forum");
  res.render("landing", { inviteValid: !!currentInvite(req.session.inviteToken), message: req.query.message || "" });
});
app.get("/invite/:token", (req, res) => {
  const invite = currentInvite(req.params.token);
  if (!invite) return res.status(404).render("invalid-invite");
  req.session.inviteToken = req.params.token;
  res.redirect("/");
});
app.get("/auth/google", (req, res, next) => {
  // Existing members can sign in without a fresh invite. New accounts are checked on callback.
  passport.authenticate("google", { scope: ["profile", "email"], prompt: "select_account" })(req, res, next);
});
app.get("/auth/google/callback", (req, res, next) => {
  // Do not create a Passport session until the invitation has been validated
  // and a database-backed user record exists.
  passport.authenticate("google", {
    failureRedirect: "/?message=google-login-failed",
    session: false
  })(req, res, () => {
    const googleUser = req.user;
    if (!googleUser) return res.redirect("/?message=google-login-failed");

    const invite = currentInvite(req.session.inviteToken);
    try {
      let user;
      if (googleUser._newGoogleUser) {
        if (!invite) return res.redirect("/?message=account-not-allowed");

        const result = db.prepare(`
          INSERT INTO users (google_id, email, display_name, avatar_url)
          VALUES (?, ?, ?, ?)
        `).run(googleUser.google_id, googleUser.email, googleUser.display_name, googleUser.avatar_url);
        user = db.prepare("SELECT id, email, display_name, avatar_url FROM users WHERE id = ?")
          .get(result.lastInsertRowid);

        // Consume the invite only after the account record is successfully created.
        const use = db.prepare(`
          UPDATE invites SET used_by = ?, used_at = CURRENT_TIMESTAMP
          WHERE id = ? AND used_by IS NULL
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        `).run(user.id, invite.id);
        if (!use.changes) {
          db.prepare("DELETE FROM users WHERE id = ?").run(user.id);
          return res.redirect("/?message=invite-already-used");
        }
      } else {
        // Existing members can log in again without needing another invitation.
        user = db.prepare("SELECT id, email, display_name, avatar_url FROM users WHERE id = ?")
          .get(googleUser.id);
        if (!user) return res.redirect("/?message=account-not-allowed");
      }

      req.session.inviteToken = null;
      req.login(user, err => {
        if (err) return next(err);
        res.redirect("/forum");
      });
    } catch (err) {
      console.error("Google account setup failed:", err);
      res.redirect("/?message=account-setup-failed");
    }
  });
});
app.post("/logout", requireLogin, (req, res, next) => {
  req.logout(err => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect("/"));
  });
});
app.get("/forum", requireLogin, (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 100);
  const category = String(req.query.category || "All");
  const sort = req.query.sort === "oldest" ? "ASC" : "DESC";
  const allowedCategories = ["All", "General", "Announcements", "Questions", "Gaming", "Showcase"];
  const selectedCategory = allowedCategories.includes(category) ? category : "All";
  const where = [];
  const params = { currentUserId: req.user.id };
  if (q) { where.push("(posts.body LIKE @query OR users.display_name LIKE @query)"); params.query = `%${q}%`; }
  if (selectedCategory !== "All") { where.push("posts.category = @category"); params.category = selectedCategory; }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const posts = db.prepare(`
    SELECT posts.id, posts.body, posts.category, posts.created_at,
      users.display_name, users.email, users.avatar_url,
      (SELECT COUNT(*) FROM post_likes WHERE post_likes.post_id = posts.id) AS like_count,
      EXISTS(SELECT 1 FROM post_likes WHERE post_likes.post_id = posts.id AND post_likes.user_id = @currentUserId) AS liked_by_me
    FROM posts JOIN users ON users.id = posts.user_id
    ${whereSql}
    ORDER BY posts.id ${sort} LIMIT 100
  `).all(params);
  const members = db.prepare("SELECT display_name, email, created_at FROM users ORDER BY id DESC LIMIT 100").all();
  const stats = {
    members: db.prepare("SELECT COUNT(*) AS count FROM users").get().count,
    posts: db.prepare("SELECT COUNT(*) AS count FROM posts").get().count,
    likes: db.prepare("SELECT COUNT(*) AS count FROM post_likes").get().count
  };
  res.render("forum", { posts, members, stats, message: req.query.message || "", q, selectedCategory, sort: sort.toLowerCase() });
});
app.post("/posts", requireLogin, (req, res) => {
  const body = String(req.body.body || "").trim();
  const categories = ["General", "Announcements", "Questions", "Gaming", "Showcase"];
  const category = categories.includes(req.body.category) ? req.body.category : "General";
  if (!body || body.length > 5000) return res.redirect("/forum?message=post-invalid");
  db.prepare("INSERT INTO posts (user_id, body, category) VALUES (?, ?, ?)").run(req.user.id, body, category);
  res.redirect("/forum");
});
app.post("/posts/:id/like", requireLogin, (req, res) => {
  const postId = Number(req.params.id);
  const exists = db.prepare("SELECT 1 FROM posts WHERE id = ?").get(postId);
  if (!exists) return res.redirect("/forum");
  const liked = db.prepare("SELECT 1 FROM post_likes WHERE user_id = ? AND post_id = ?").get(req.user.id, postId);
  if (liked) db.prepare("DELETE FROM post_likes WHERE user_id = ? AND post_id = ?").run(req.user.id, postId);
  else db.prepare("INSERT OR IGNORE INTO post_likes (user_id, post_id) VALUES (?, ?)").run(req.user.id, postId);
  res.redirect(req.get("referer") && req.get("referer").startsWith(BASE_URL) ? req.get("referer") : "/forum");
});
app.post("/admin/invites", requireLogin, requireAdmin, (req, res) => {
  const token = crypto.randomBytes(24).toString("base64url");
  const hours = Math.max(1, Math.min(720, Number(req.body.expiryHours) || 168));
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString().replace("T", " ").replace("Z", "");
  db.prepare("INSERT INTO invites (token_hash, created_by, expires_at) VALUES (?, ?, ?)").run(hashToken(token), req.user.email, expiresAt);
  res.render("invite-created", { inviteUrl: `${BASE_URL}/invite/${token}`, expiresAt });
});
app.post("/admin/posts/:id/delete", requireLogin, requireAdmin, (req, res) => {
  db.prepare("DELETE FROM posts WHERE id = ?").run(Number(req.params.id));
  res.redirect("/forum");
});
app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Private forum running at ${BASE_URL}`));
