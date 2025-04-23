const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const db = require('./database');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());

// Register a new user
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`;

    db.run(sql, [username, email, hashedPassword], function (err) {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.json({ id: this.lastID, username, email });
    });
});

// Login user
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = `SELECT * FROM users WHERE email = ?`;
    db.get(sql, [email], async (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: "User not found" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        res.json({ message: "Login successful", user: { id: user.id, username: user.username, email: user.email } });
    });
});

app.get('/user/:id', (req, res) => {
        const sql = `SELECT * FROM users WHERE id = ?`;
        db.get(sql, [req.params.id], (err, row) => {
            if (err) {
                return res.status(400).json({ error: err.message });
            }
            res.json(row);
        });
    });
app.delete('/user/:id', (req, res) => {
            const sql = `DELETE FROM users WHERE id = ?`;
            db.run(sql, [req.params.id], function (err) {
                if (err) {
                    return res.status(400).json({ error: err.message });
                }
                res.json({ message: 'User deleted' });
            });
        });
app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
        
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
