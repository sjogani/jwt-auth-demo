require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt'); 
const jwt = require('jsonwebtoken'); 
const db = require('./db'); // Database connection
const authenticateJWT = require('./middleware/authenticate'); // JWT Authentication Middleware
const requestLogger = require('./middleware/logger'); // Logging Middleware
const rateLimiter = require('./middleware/rateLimiter'); // Rate Limiting Middleware
const { encryptData, decryptData } = require('./cryptoUtils'); 

const app = express();

app.use(express.json());
app.use(cors());
app.use(requestLogger); // Logs all requests
app.use(rateLimiter); // Limits request rate

// 🔹 Middleware to Decrypt Incoming Requests
app.use((req, res, next) => {
    if (req.body && req.body.encrypted) {
        try {
            req.body = decryptData(req.body.encrypted);
        } catch (error) {
            return res.status(400).json({ error: "Invalid encrypted request" });
        }
    }
    next();
});

// 📝 Register User
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword]);
        
        const response = encryptData({ message: 'User registered successfully' });
        res.status(201).json({ encrypted: response });
    } catch (error) {
        const response = encryptData({ error: 'Database error', details: error });
        res.status(500).json({ encrypted: response }); 
    }
});

// 🔑 Login & Generate JWT
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const [user] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
        
        if (user.length === 0|| !(await bcrypt.compare(password, user[0].password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const token = jwt.sign({ username: user[0].username }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        const response = encryptData({ token });
        res.json({ encrypted: response });
    } catch (error) {
        const response = encryptData({ error: 'Database error', details: error });
        res.status(500).json({ encrypted: response });
    }
});

// 📝 Create Post API (with Hashtags & Friends Extraction)
app.post('/create-post', authenticateJWT, async (req, res) => {
    const { title, content } = req.body;
    const created_by = req.user.username;

    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required' });
    }

    try {
        // Insert post into database
        const [postResult] = await db.query("INSERT INTO post_masters (title, content, created_by) VALUES (?, ?, ?)", 
            [title, content, created_by]);
        const postId = postResult.insertId;

        // Extract & Store Hashtags
        const extractedHashtags = [...new Set(title.match(/#\w+/g) || [])];
        for (const hashtag of extractedHashtags) {
            let [hashRows] = await db.query("SELECT id FROM hash_masters WHERE hashtag = ?", [hashtag]);
            if (hashRows.length === 0) {
                const [insertResult] = await db.query("INSERT INTO hash_masters (hashtag) VALUES (?)", [hashtag]);
                hashRows = [{ id: insertResult.insertId }];
            }
            await db.query("INSERT INTO post_hash (post_id, hashtag_id) VALUES (?, ?)", [postId, hashRows[0].id]);
        }

        // Extract & Store Friends
        const mentionedFriends = [...new Set(title.match(/@\w+/g) || [])];
        for (const friend of mentionedFriends) {
            const friendUsername = friend.substring(1); // Remove '@'
            const [friendRows] = await db.query(
                "SELECT * FROM followers WHERE (user_id = ? AND follower_id = ?) OR (user_id = ? AND follower_id = ?)", 
                [created_by, friendUsername, friendUsername, created_by]
            );

            if (friendRows.length > 0) {
                await db.query("INSERT INTO post_friend_details (post_id, friend_username) VALUES (?, ?)", [postId, friendUsername]);
            }
        }

        const response = encryptData({ message: 'Post created successfully', postId, extractedHashtags, mentionedFriends });
        res.status(201).json({ encrypted: response });
    } catch (error) {
        const response = encryptData({ error: 'Database error', details: error });
        res.status(500).json({ encrypted: response });
    }
});

// 🔍 API to Validate JWT
app.get('/validate-token', authenticateJWT, (req, res) => {
    res.json({ message: 'Token is valid', user: req.user });
});

// 🔐 Protected Route
app.get('/protected', authenticateJWT, (req, res) => {
    res.json({ message: 'Protected content', user: req.user });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
