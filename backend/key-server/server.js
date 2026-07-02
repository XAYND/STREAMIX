require("dotenv").config({
  path: require("path").join(__dirname, ".env")
});

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { findUserByEmail, createUser, hasVideoAccess, seedDemoUser } = require("./db");

const rootDir = path.join(__dirname, "..", "..");

const app = express();

const PORT = Number(process.env.PORT || 3001);

const TOKEN_SECRET = process.env.TOKEN_SECRET;
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 300);

const SESSION_JWT_SECRET = process.env.SESSION_JWT_SECRET;
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 3600);

const ADMIN_LOGS_TOKEN = process.env.ADMIN_LOGS_TOKEN;

const VIDEO_ID = process.env.VIDEO_ID || "streamix-demo";

const DEMO_USER_EMAIL = process.env.DEMO_USER_EMAIL || "demo@streamix.local";
const DEMO_USER_PASSWORD = process.env.DEMO_USER_PASSWORD || "StreamixDemo123!";

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

if (!TOKEN_SECRET || !SESSION_JWT_SECRET || !ADMIN_LOGS_TOKEN) {
  console.error("Missing required environment variables.");
  console.error("Required: TOKEN_SECRET, SESSION_JWT_SECRET, ADMIN_LOGS_TOKEN");
  process.exit(1);
}

seedDemoUser(DEMO_USER_EMAIL, DEMO_USER_PASSWORD, VIDEO_ID);

app.use(express.json());

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS origin not allowed"));
    },
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Admin-Token"
    ],
    methods: ["GET", "POST", "OPTIONS"]
  })
);

const tokenLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many token requests",
    reason: "rate_limited"
  }
});

const keyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many key requests",
    reason: "rate_limited"
  }
});

const logsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many log requests",
    reason: "rate_limited"
  }
});

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: "Too many auth requests",
    reason: "rate_limited"
  }
});

const logsDir = path.join(__dirname, "logs");
const logPath = path.join(logsDir, "access.log");

if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

function createRequestId() {
  return crypto.randomBytes(8).toString("hex");
}

function base64urlJson(input) {
  return Buffer.from(JSON.stringify(input)).toString("base64url");
}

function sign(data) {
  return crypto
    .createHmac("sha256", TOKEN_SECRET)
    .update(data)
    .digest("base64url");
}

function createToken(payload) {
  const header = {
    alg: "HS256",
    typ: "JWT"
  };

  const encodedHeader = base64urlJson(header);
  const encodedPayload = base64urlJson(payload);
  const signature = sign(`${encodedHeader}.${encodedPayload}`);

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyToken(token) {
  if (!token) {
    return {
      valid: false,
      reason: "missing_token"
    };
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    return {
      valid: false,
      reason: "malformed_token"
    };
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const expectedSignature = sign(`${encodedHeader}.${encodedPayload}`);

  const signatureBuffer = Buffer.from(signature);
  const expectedSignatureBuffer = Buffer.from(expectedSignature);

  if (
    signatureBuffer.length !== expectedSignatureBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, expectedSignatureBuffer)
  ) {
    return {
      valid: false,
      reason: "invalid_signature"
    };
  }

  let payload;

  try {
    payload = JSON.parse(
      Buffer.from(encodedPayload, "base64url").toString("utf-8")
    );
  } catch {
    return {
      valid: false,
      reason: "invalid_payload"
    };
  }

  const now = Math.floor(Date.now() / 1000);

  if (!payload.exp || payload.exp < now) {
    return {
      valid: false,
      reason: "expired_token"
    };
  }

  if (!payload.iat || payload.iat > now + 10) {
    return {
      valid: false,
      reason: "invalid_iat"
    };
  }

  if (payload.video !== VIDEO_ID) {
    return {
      valid: false,
      reason: "video_not_allowed"
    };
  }

  if (payload.scope !== "hls:key:read") {
    return {
      valid: false,
      reason: "invalid_scope"
    };
  }

  return {
    valid: true,
    payload
  };
}

function writeLog(event) {
  fs.appendFileSync(logPath, JSON.stringify(event) + "\n");
}

function buildLog(req, extra) {
  return {
    timestamp: new Date().toISOString(),
    requestId: createRequestId(),
    ip: req.ip,
    userAgent: req.headers["user-agent"] || "unknown",
    service: "streamix-key-server",
    ...extra
  };
}

app.get("/health", (req, res) => {
  res.json({
    status: "online",
    service: "streamix-key-server",
    port: PORT,
    security: {
      httpsEnabled: true,
      tokenHeaderRequired: true,
      tokenTtlSeconds: TOKEN_TTL_SECONDS,
      manifestExposesToken: false,
      logsProtected: true,
      rateLimitEnabled: true
    }
  });
});

app.post("/auth/register", authLimiter, (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password || password.length < 8) {
    return res.status(400).json({
      error: "Bad request",
      reason: "email and password (8+ chars) are required"
    });
  }

  if (findUserByEmail(email)) {
    return res.status(409).json({
      error: "Conflict",
      reason: "email_already_registered"
    });
  }

  // Demo simplification: new accounts are auto-granted access to VIDEO_ID.
  // A real deployment would leave video_access empty and grant it out of band.
  createUser(email, password, [VIDEO_ID]);

  const log = buildLog(req, {
    route: "/auth/register",
    user: email,
    video: VIDEO_ID,
    access: "granted",
    reason: "account_created"
  });

  writeLog(log);

  res.status(201).json({ email });
});

app.post("/auth/login", authLimiter, (req, res) => {
  const { email, password } = req.body || {};

  const user = email ? findUserByEmail(email) : null;
  const passwordOk = user ? bcrypt.compareSync(password || "", user.password_hash) : false;

  if (!user || !passwordOk) {
    const log = buildLog(req, {
      route: "/auth/login",
      user: email || "unknown",
      video: VIDEO_ID,
      access: "denied",
      reason: "invalid_credentials"
    });

    writeLog(log);

    return res.status(401).json({
      error: "Unauthorized",
      reason: "invalid_credentials"
    });
  }

  const sessionToken = jwt.sign(
    { sub: user.id, email: user.email },
    SESSION_JWT_SECRET,
    { expiresIn: SESSION_TTL_SECONDS }
  );

  const log = buildLog(req, {
    route: "/auth/login",
    user: user.email,
    video: VIDEO_ID,
    access: "granted",
    reason: "login_success"
  });

  writeLog(log);

  res.json({
    session_token: sessionToken,
    token_type: "Bearer",
    expires_in: SESSION_TTL_SECONDS,
    email: user.email
  });
});

app.get("/token", tokenLimiter, (req, res) => {
  const authHeader = req.headers.authorization || "";
  const sessionToken = authHeader.startsWith("Bearer ")
    ? authHeader.slice("Bearer ".length)
    : null;

  let session = null;

  try {
    session = sessionToken ? jwt.verify(sessionToken, SESSION_JWT_SECRET) : null;
  } catch {
    session = null;
  }

  if (!session) {
    const log = buildLog(req, {
      route: "/token",
      user: "unknown",
      video: VIDEO_ID,
      access: "denied",
      reason: "invalid_session"
    });

    writeLog(log);

    return res.status(401).json({
      error: "Unauthorized",
      reason: "invalid_session"
    });
  }

  if (!hasVideoAccess(session.sub, VIDEO_ID)) {
    const log = buildLog(req, {
      route: "/token",
      user: session.email,
      video: VIDEO_ID,
      access: "denied",
      reason: "video_not_authorized"
    });

    writeLog(log);

    return res.status(403).json({
      error: "Forbidden",
      reason: "video_not_authorized"
    });
  }

  const now = Math.floor(Date.now() / 1000);

  const payload = {
    user: session.email,
    video: VIDEO_ID,
    scope: "hls:key:read",
    iat: now,
    exp: now + TOKEN_TTL_SECONDS
  };

  const token = createToken(payload);

  const log = buildLog(req, {
    route: "/token",
    user: session.email,
    video: VIDEO_ID,
    access: "granted",
    reason: "temporary_token_issued"
  });

  writeLog(log);

  res.json({
    token,
    token_type: "Bearer",
    expires_in: TOKEN_TTL_SECONDS,
    user: payload.user,
    video: payload.video,
    scope: payload.scope
  });
});

app.get("/key", keyLimiter, (req, res) => {
  const authHeader = req.headers.authorization || "";

  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice("Bearer ".length)
    : null;

  const verification = verifyToken(token);

  const log = buildLog(req, {
    route: "/key",
    user: verification.valid ? verification.payload.user : "unknown",
    video: verification.valid ? verification.payload.video : VIDEO_ID,
    access: verification.valid ? "granted" : "denied",
    reason: verification.valid ? "valid_token" : verification.reason
  });

  writeLog(log);

  if (!verification.valid) {
    return res.status(403).json({
      error: "Access denied",
      reason: verification.reason
    });
  }

  const keyPath = path.join(rootDir, "enc.key");

  if (!fs.existsSync(keyPath)) {
    return res.status(500).json({
      error: "AES key not found"
    });
  }

  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(keyPath);
});

app.get("/logs", logsLimiter, (req, res) => {
  const adminToken = req.headers["x-admin-token"];

  if (adminToken !== ADMIN_LOGS_TOKEN) {
    const log = buildLog(req, {
      route: "/logs",
      user: "unknown",
      video: VIDEO_ID,
      access: "denied",
      reason: "invalid_admin_token"
    });

    writeLog(log);

    return res.status(401).json({
      error: "Unauthorized",
      reason: "invalid_admin_token"
    });
  }

  if (!fs.existsSync(logPath)) {
    return res.json([]);
  }

  const lines = fs
    .readFileSync(logPath, "utf-8")
    .split("\n")
    .filter(Boolean)
    .slice(-50)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { raw: line };
      }
    });

  res.json(lines);
});

const sslOptions = {
  key: fs.readFileSync(path.join(rootDir, "certs", "localhost-key.pem")),
  cert: fs.readFileSync(path.join(rootDir, "certs", "localhost.pem"))
};

https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`Key server running on https://localhost:${PORT}`);
});