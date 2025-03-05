require('dotenv').config();
const express = require('express');
const cors = require('cors');
const db = require('./db'); // Database connection

const app = express();
app.use(express.json());
app.use(cors());

// 📝 Register User
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword]);
        res.status(201).send('User registered');
    } catch (error) {
        res.status(500).json({ error: 'Database error', details: error });
    }
});

// 🔑 Login & Generate JWT
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
        const user = rows[0];

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Database error', details: error });
    }
});


// 📝 Create Post API
app.post('/create-post', authenticateJWT, async (req, res) => {
    const { title, content } = req.body;
    const created_by = req.user.username;

    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required' });
    }

    try {
        // Insert post
        const [postResult] = await db.query("INSERT INTO post_masters (title, content, created_by) VALUES (?, ?, ?)", 
            [title, content, created_by]);
        const postId = postResult.insertId;

        // Extract hashtags
        const extractedHashtags = [...new Set(title.match(/#\w+/g) || [])];
        for (const hashtag of extractedHashtags) {
            let [hashRows] = await db.query("SELECT id FROM hash_masters WHERE hashtag = ?", [hashtag]);
            if (hashRows.length === 0) {
                const [insertResult] = await db.query("INSERT INTO hash_masters (hashtag) VALUES (?)", [hashtag]);
                hashRows = [{ id: insertResult.insertId }];
            }
            await db.query("INSERT INTO post_hash (post_id, hashtag_id) VALUES (?, ?)", [postId, hashRows[0].id]);
        }

        res.status(201).json({ message: 'Post created successfully', postId, extractedHashtags });
    } catch (error) {
        res.status(500).json({ error: 'Database error', details: error });
    }
});


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
