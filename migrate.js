const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const sql = fs.readFileSync(path.join(__dirname, 'MIGRATION.sql'), 'utf8');
const dbFile = path.join(__dirname, 'database.db');

const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Cannot open DB', err);
    process.exit(1);
  }
});

db.exec(sql, (err) => {
  if (err) {
    console.error('Migration error:', err);
  } else {
    console.log('Migration ran successfully. DB file:', dbFile);
  }
  db.close();
});
