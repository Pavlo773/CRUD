const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();

// --- НАЛАШТУВАННЯ ---

// Налаштування сесій
app.use(session({
  secret: 'SUPER_SECRET_KEY_FOR_SESSIONS', 
  resave: false,
  saveUninitialized: false,
  cookie: { 
      secure: false, // true для HTTPS
      httpOnly: true, // Захист від XSS
      sameSite: 'Lax'
  } 
}));

// CORS: Дозволяємо передачу cookie. Оскільки фронтенд тепер обслуговується
// з того ж джерела (http://localhost:3001), CORS потрібен лише для 
// встановлення credentials: true для роботи сесій.
app.use(cors({
    origin: 'http://localhost:3001', 
    credentials: true 
}));

app.use(bodyParser.json());

const dbFile = path.join(__dirname, 'database.db');
const db = new sqlite3.Database(dbFile, (err) => {
  if (err) {
    console.error('Failed to open DB', err);
    process.exit(1);
  }
});

const HASH_SALT_ROUNDS = 10;

// --- ОБСЛУГОВУВАННЯ СТАТИЧНИХ ФАЙЛІВ (ВАРІАНТ А) ---

// Обслуговуємо index.html як кореневий маршрут
const INDEX_HTML_PATH = path.join(__dirname, 'index.html');

app.get('/', (req, res) => {
  res.sendFile(INDEX_HTML_PATH, (err) => {
    if (err) {
      console.error('Failed to send index.html:', err);
      // Якщо index.html не знайдено, повертаємо помилку
      res.status(500).send('Error loading frontend file. Check if index.html is in the same directory as server.js.');
    }
  });
});

// --- ДОПОМІЖНІ ФУНКЦІЇ ДЛЯ ПОМИЛОК І ВАЛІДАЦІЇ ---

function sendDbError(res, err) {
  console.error(err);
  return res.status(500).json({ error: 'Database error' });
}

function formatValidationErrors(errors) {
  const fieldErrors = errors.array().map(err => {
    let code = 'INVALID_VALUE';
    if (err.msg.includes('required')) {
        code = 'MISSING_FIELD';
    } else if (err.msg.includes('between')) {
        code = 'OUT_OF_RANGE';
    } else if (err.msg.includes('integer') || err.msg.includes('string') || err.msg.includes('date')) {
        code = 'INVALID_TYPE';
    }
    
    return {
      field: err.path,
      code: code,
      message: err.msg
    };
  });

  return {
    timestamp: new Date().toISOString(),
    status: 400,
    error: 'Bad Request',
    fieldErrors: fieldErrors
  };
}

// --- MIDDLEWARE ДЛЯ ЗАХИСТУ ---

function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized', message: 'Authentication required to access this resource.' });
    }
}


// --- ПРАВИЛА ВАЛІДАЦІЇ DROID ---

const droidValidationRules = [
    body('name').isLength({ min: 3, max: 50 }).withMessage('name is required and must be between 3 and 50 characters'),
    body('manufacturer').optional({ nullable: true }).isString().isLength({ max: 50 }).withMessage('manufacturer must be a string up to 50 characters'),
    body('year_production').optional({ nullable: true }).isInt({ min: 1900, max: 2100 }).withMessage('year_production must be a valid integer between 1900 and 2100'),
    body('status').optional({ nullable: true }).isString().isLength({ max: 50 }).withMessage('status must be a string up to 50 characters'),
    body('model').optional({ nullable: true }).isString().isLength({ max: 50 }).withMessage('model must be a string up to 50 characters'),
    body('battery_level').optional({ nullable: true }).isInt({ min: 0, max: 100 }).withMessage('battery_level must be an integer between 0 and 100'),
    body('mission').optional({ nullable: true }).isString().isLength({ max: 255 }).withMessage('mission must be a string up to 255 characters'),
    body('last_maintenance').optional({ nullable: true }).isISO8601().withMessage('last_maintenance must be a valid date in YYYY-MM-DD format'),
];

const droidUpdateValidationRules = [
    body('name').optional({ checkFalsy: true }).isLength({ min: 3, max: 50 }).withMessage('name must be between 3 and 50 characters'),
    body('manufacturer').optional({ nullable: true }).isString().isLength({ max: 50 }).withMessage('manufacturer must be a string up to 50 characters'),
    body('year_production').optional({ nullable: true }).isInt({ min: 1900, max: 2100 }).withMessage('year_production must be a valid integer between 1900 and 2100'),
    body('status').optional({ nullable: true }).isString().isLength({ max: 50 }).withMessage('status must be a string up to 50 characters'),
    body('model').optional({ nullable: true }).isString().isLength({ max: 50 }).withMessage('model must be a string up to 50 characters'),
    body('battery_level').optional({ nullable: true }).isInt({ min: 0, max: 100 }).withMessage('battery_level must be an integer between 0 and 100'),
    body('mission').optional({ nullable: true }).isString().isLength({ max: 255 }).withMessage('mission must be a string up to 255 characters'),
    body('last_maintenance').optional({ nullable: true }).isISO8601().withMessage('last_maintenance must be a valid date in YYYY-MM-DD format'),
];


// --- МАРШРУТИ АУТЕНТИФІКАЦІЇ ---

app.get('/status', (req, res) => {
    if (req.session.userId) {
        db.get('SELECT username FROM users WHERE id = ?', [req.session.userId], (err, user) => {
            if (err) return res.json({ isLoggedIn: true, error: 'User lookup failed' });
            res.json({ isLoggedIn: true, username: user ? user.username : 'Unknown' });
        });
    } else {
        res.json({ isLoggedIn: false });
    }
});


app.post('/register', 
    body('username').isLength({ min: 3, max: 20 }).withMessage('Username must be 3-20 characters'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json(formatValidationErrors(errors));

        const { username, password } = req.body;
        
        db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) return sendDbError(res, err);
            if (row) {
                return res.status(409).json({ error: 'Conflict', message: 'User with this username already exists.' });
            }

            const password_hash = await bcrypt.hash(password, HASH_SALT_ROUNDS);
            
            db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, password_hash], function(err) {
                if (err) return sendDbError(res, err);

                req.session.userId = this.lastID;
                res.status(201).json({ message: 'User registered successfully', username: username });
            });
        });
    }
);

app.post('/login', 
    body('username').notEmpty().withMessage('Username is required'),
    body('password').notEmpty().withMessage('Password is required'),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json(formatValidationErrors(errors));
        
        const { username, password } = req.body;

        db.get('SELECT id, password_hash FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) return sendDbError(res, err);
            if (!row) {
                return res.status(401).json({ error: 'Unauthorized', message: 'Invalid username or password.' });
            }

            const match = await bcrypt.compare(password, row.password_hash);

            if (match) {
                req.session.userId = row.id;
                res.json({ message: 'Login successful', username: username });
            } else {
                res.status(401).json({ error: 'Unauthorized', message: 'Invalid username or password.' });
            }
        });
    }
);

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).json({ error: 'Logout failed' });
        res.json({ message: 'Logged out successfully' });
    });
});


// --- МАРШРУТИ CRUD DROID (ЗАХИЩЕНІ) ---

// Застосовуємо middleware isAuthenticated до всіх маршрутів Droids
app.get('/droids', isAuthenticated, (req, res) => {
  const userId = req.session.userId;
  db.all('SELECT * FROM droids WHERE user_id = ? ORDER BY id DESC', [userId], (err, rows) => {
    if (err) return sendDbError(res, err);
    res.json(rows);
  });
});

app.get('/droids/:id', isAuthenticated, (req, res) => {
  db.get('SELECT * FROM droids WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return sendDbError(res, err);
    if (!row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

app.post('/droids', isAuthenticated, droidValidationRules,
  (req, res) => {
    // ... валідація ...
    const userId = req.session.userId; // ID поточного користувача
    const { name, manufacturer, year_production, status, model, battery_level, mission, last_maintenance } = req.body;
    
    const sql = 'INSERT INTO droids (name, manufacturer, year_production, status, model, battery_level, mission, last_maintenance, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
    
    db.run(sql, [name, manufacturer || null, year_production || null, status || null, model || null, battery_level || null, mission || null, last_maintenance || null, userId], function(err) {
      if (err) return sendDbError(res, err);
      const id = this.lastID;
      db.get('SELECT * FROM droids WHERE id = ?', [id], (err, row) => {
        if (err) return sendDbError(res, err);
        res.status(201).json(row);
      });
    });
  }
);

app.put('/droids/:id', isAuthenticated, droidUpdateValidationRules,
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json(formatValidationErrors(errors));

    const id = req.params.id;
    db.get('SELECT * FROM droids WHERE id = ?', [id], (err, row) => {
      if (err) return sendDbError(res, err);
      if (!row) return res.status(404).json({ error: 'Not found' });

      const updated = {
        name: req.body.name !== undefined ? req.body.name : row.name,
        manufacturer: req.body.manufacturer !== undefined ? req.body.manufacturer : row.manufacturer,
        year_production: req.body.year_production !== undefined ? req.body.year_production : row.year_production,
        status: req.body.status !== undefined ? req.body.status : row.status,
        model: req.body.model !== undefined ? req.body.model : row.model,
        battery_level: req.body.battery_level !== undefined ? req.body.battery_level : row.battery_level,
        mission: req.body.mission !== undefined ? req.body.mission : row.mission,
        last_maintenance: req.body.last_maintenance !== undefined ? req.body.last_maintenance : row.last_maintenance
      };
      
      const sql = 'UPDATE droids SET name = ?, manufacturer = ?, year_production = ?, status = ?, model = ?, battery_level = ?, mission = ?, last_maintenance = ? WHERE id = ?';
      
      db.run(sql, [updated.name || null, updated.manufacturer || null, updated.year_production || null, updated.status || null, updated.model || null, updated.battery_level || null, updated.mission || null, updated.last_maintenance || null, id], function(err) {
        if (err) return sendDbError(res, err);
        db.get('SELECT * FROM droids WHERE id = ?', [id], (err, row) => {
          if (err) return sendDbError(res, err);
          res.json(row);
        });
      });
    });
  }
);

app.delete('/droids/:id', isAuthenticated, (req, res) => {
  const userId = req.session.userId;
  db.run('DELETE FROM droids WHERE id = ? AND user_id = ?', [req.params.id, userId], function(err) {
    if (err) return sendDbError(res, err);
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.status(204).send();
  });
});

// Health check для CI/CD smoketest
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'UP', service: 'Droids API' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;