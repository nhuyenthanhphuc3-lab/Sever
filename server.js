const express = require("express");
const helmet = require("helmet");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
const DATA_DIR = path.join(__dirname, "storage");
const TOKENS_FILE = path.join(DATA_DIR, "tokens.json");
const SOURCE_FILE = path.join(DATA_DIR, "source.lua");

fs.mkdirSync(DATA_DIR, { recursive: true });

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "256kb" }));

function loadTokens() {
  try {
    return JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8"));
  } catch {
    return {};
  }
}

function saveTokens(tokens) {
  fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2));
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function adminOK(req) {
  const supplied = req.get("x-admin-secret") || "";
  if (!ADMIN_SECRET || !supplied) return false;
  return crypto.timingSafeEqual(
    Buffer.from(supplied),
    Buffer.from(ADMIN_SECRET)
  );
}

const rate = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || "unknown";
  const now = Date.now();
  const item = rate.get(ip) || { start: now, count: 0 };

  if (now - item.start > 60_000) {
    item.start = now;
    item.count = 0;
  }

  item.count++;
  rate.set(ip, item);

  if (item.count > 60) {
    return res.status(429).json({ ok: false, error: "rate_limited" });
  }
  next();
}

app.use(rateLimit);

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "phucmax-verify-server",
    time: new Date().toISOString()
  });
});

// Browser visiting this path never receives the Lua source.
app.get("/executors/:id.lua", (req, res) => {
  res.status(403).json({
    ok: false,
    error: "direct_access_denied",
    message: "Use the verification API."
  });
});

// Verify a token and return the private Lua source.
app.post("/api/verify", (req, res) => {
  const token = typeof req.body?.token === "string"
    ? req.body.token.trim()
    : "";

  if (!token) {
    return res.status(400).json({ ok: false, error: "missing_token" });
  }

  const tokens = loadTokens();
  const record = tokens[hashToken(token)];

  if (!record) {
    return res.status(401).json({ ok: false, error: "invalid_token" });
  }

  if (record.revoked) {
    return res.status(401).json({ ok: false, error: "token_revoked" });
  }

  if (record.expiresAt && Date.now() >= record.expiresAt) {
    return res.status(401).json({ ok: false, error: "token_expired" });
  }

  if (!fs.existsSync(SOURCE_FILE)) {
    return res.status(503).json({ ok: false, error: "source_not_configured" });
  }

  const source = fs.readFileSync(SOURCE_FILE, "utf8");
  return res.json({
    ok: true,
    source,
    sha256: hashToken(source)
  });
});

// Create a token.
// Body: { "days": 7, "label": "user1" }
app.post("/api/admin/create-token", (req, res) => {
  if (!adminOK(req)) {
    return res.status(401).json({ ok: false, error: "admin_unauthorized" });
  }

  const days = Math.max(1, Math.min(3650, Number(req.body?.days || 7)));
  const label = String(req.body?.label || "token").slice(0, 80);

  const token = crypto.randomBytes(32).toString("base64url");
  const tokens = loadTokens();

  tokens[hashToken(token)] = {
    label,
    createdAt: Date.now(),
    expiresAt: Date.now() + days * 86400000,
    revoked: false
  };

  saveTokens(tokens);

  res.json({
    ok: true,
    token,
    expiresAt: new Date(Date.now() + days * 86400000).toISOString()
  });
});

// Revoke a token.
// Body: { "token": "..." }
app.post("/api/admin/revoke-token", (req, res) => {
  if (!adminOK(req)) {
    return res.status(401).json({ ok: false, error: "admin_unauthorized" });
  }

  const token = typeof req.body?.token === "string"
    ? req.body.token.trim()
    : "";

  if (!token) {
    return res.status(400).json({ ok: false, error: "missing_token" });
  }

  const tokens = loadTokens();
  const key = hashToken(token);

  if (!tokens[key]) {
    return res.status(404).json({ ok: false, error: "token_not_found" });
  }

  tokens[key].revoked = true;
  tokens[key].revokedAt = Date.now();
  saveTokens(tokens);

  res.json({ ok: true });
});

// Upload/replace the private Lua source.
// Body: { "source": "print('hello')" }
app.post("/api/admin/source", (req, res) => {
  if (!adminOK(req)) {
    return res.status(401).json({ ok: false, error: "admin_unauthorized" });
  }

  const source = typeof req.body?.source === "string"
    ? req.body.source
    : "";

  if (!source) {
    return res.status(400).json({ ok: false, error: "missing_source" });
  }

  fs.writeFileSync(SOURCE_FILE, source, "utf8");

  res.json({
    ok: true,
    sha256: hashToken(source),
    bytes: Buffer.byteLength(source, "utf8")
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Verify server listening on ${PORT}`);
});
