const db = require('../db');

const requestLogger = async (req, res, next) => {
    try {
        const { method, url } = req;
        const timestamp = new Date();

        await db.query(
            "INSERT INTO request_logs (method, url, timestamp) VALUES (?, ?, ?)", 
            [method, url, timestamp]
        );

    } catch (error) {
        console.error('Logging error:', error);
    }

    next();
};

module.exports = requestLogger;
