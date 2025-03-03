require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());


const users = [
    { username: "testuser", password: "$2b$10$C4r1wj/KaLb6n9SL29Z5i.hO4uoxfYTNBoZa2d8DylfdvCO46/nhm" }
];

const posts = [];  // Array to store posts
const hashtags = [];  // Array to store hashtags
const postHashtags = [];  // Array to store post-hashtag relationships
const followers = [{ user_id: "testuser", follower_id: "john_doe" }]; // Array for user relationships
const postFriends = [];  // Array to store post-friend relationships

// 🔐 Middleware to Validate JWT
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication failed. No token provided.' });
    }

    const token = authHeader.split(' ')[1]; // Extract the token

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // Attach user data to request
        next(); // Proceed to the next middleware/route handler
    } catch (error) {
        return res.status(403).json({ error: 'Authentication failed. Invalid or expired token.' });
    }
};


// 📝 Register User
app.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    users.push({ username: req.body.username, password: hashedPassword });
    res.status(201).send('User registered');
});

// 🔑 Login & Generate JWT
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    // Check if user exists
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create JWT Payload (includes user info)
    const payload = { username: user.username };

    // Generate JWT with expiration
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

    // Send token in response
    res.json({ token });
});

// 📝 Create Post API (with Hashtags & Friends Extraction)
app.post('/create-post', authenticateJWT, (req, res) => {
    const { title, content } = req.body;
    const created_by = req.user.username;

    if (!title || !content) {
        return res.status(400).json({ error: 'Title and content are required' });
    }

    // Store post
    const postId = posts.length + 1;
    posts.push({ postId, title, content, created_by });

    // Extract hashtags from title (words starting with #)
    const extractedHashtags = [...new Set(title.match(/#\w+/g) || [])];

    // Store hashtags if they don’t exist
    extractedHashtags.forEach(hashtag => {
        if (!hashtags.includes(hashtag)) {
            hashtags.push(hashtag);
        }
        postHashtags.push({ postId, hashtag });
    });

    // Extract friend mentions from title (words starting with @)
    const mentionedFriends = [...new Set(title.match(/@\w+/g) || [])];

    mentionedFriends.forEach(friend => {
        const friendUsername = friend.substring(1); // Remove @
        const isFriend = followers.some(f => 
            (f.user_id === created_by && f.follower_id === friendUsername) ||
            (f.user_id === friendUsername && f.follower_id === created_by)
        );

        if (isFriend) {
            postFriends.push({ postId, friendUsername });
        }
    });

    res.status(201).json({ message: 'Post created successfully', postId, extractedHashtags, mentionedFriends });
});

// 🔍 API to Validate JWT
app.get('/validate-token', authenticateJWT, (req, res) => {
    res.json({ message: 'Token is valid', user: req.user });
});


// 🔐 Protected Route
app.get('/protected', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        res.json({ message: 'Protected content', user: decoded });
    } catch (error) {
        res.status(403).json({ error: 'Invalid or expired token' });
    }
});



// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(` Server running on port ${PORT}`));
