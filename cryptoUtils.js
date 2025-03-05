require('dotenv').config();

const CryptoJS = require("crypto-js");

const SECRET_KEY = process.env.CRYPTO_SECRET_KEY ;

// Encrypt Data
function encryptData(data) {
    return CryptoJS.AES.encrypt(JSON.stringify(data), SECRET_KEY).toString();
}

// Decrypt Data
function decryptData(encryptedData) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, SECRET_KEY);
    return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

module.exports = { encryptData, decryptData };
