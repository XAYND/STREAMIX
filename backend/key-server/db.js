const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const dataDir = path.join(__dirname, "data");

if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(path.join(dataDir, "streamix.db"));

db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS video_access (
    user_id INTEGER NOT NULL REFERENCES users(id),
    video_id TEXT NOT NULL,
    granted_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, video_id)
  );
`);

function findUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(email);
}

function createUser(email, password, videoIds = []) {
  const passwordHash = bcrypt.hashSync(password, 10);

  const insertUser = db.prepare(
    "INSERT INTO users (email, password_hash) VALUES (?, ?)"
  );
  const grantAccess = db.prepare(
    "INSERT OR IGNORE INTO video_access (user_id, video_id) VALUES (?, ?)"
  );

  const createWithAccess = db.transaction((email, passwordHash, videoIds) => {
    const info = insertUser.run(email, passwordHash);
    for (const videoId of videoIds) {
      grantAccess.run(info.lastInsertRowid, videoId);
    }
    return info.lastInsertRowid;
  });

  const id = createWithAccess(email, passwordHash, videoIds);
  return { id, email };
}

function hasVideoAccess(userId, videoId) {
  const row = db
    .prepare("SELECT 1 FROM video_access WHERE user_id = ? AND video_id = ?")
    .get(userId, videoId);
  return Boolean(row);
}

// Demo convenience: seed one user with access to VIDEO_ID so the app is
// usable out of the box. Real onboarding would go through /auth/register.
function seedDemoUser(email, password, videoId) {
  if (findUserByEmail(email)) return;

  createUser(email, password, [videoId]);
  console.log(`Seeded demo user "${email}" / "${password}" with access to video "${videoId}"`);
}

module.exports = {
  findUserByEmail,
  createUser,
  hasVideoAccess,
  seedDemoUser,
};
