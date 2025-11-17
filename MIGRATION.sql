DROP TABLE IF EXISTS droids;

CREATE TABLE IF NOT EXISTS droids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  manufacturer TEXT,
  year_production INTEGER,
  status TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  model TEXT,
  battery_level INTEGER,
  mission TEXT,
  last_maintenance TEXT,
  user_id INTEGER, -- <--- НОВЕ ПОЛЕ
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);