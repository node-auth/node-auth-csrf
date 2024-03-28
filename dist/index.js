"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
/**
 * Generate csrf token
 * @returns token
 */
function generateToken(secret) {
    const timestamp = Date.now().toString();
    const hash = crypto_1.default.createHmac('sha256', secret)
        .update(timestamp)
        .digest('hex');
    return `${timestamp}-${hash}`;
}
/**
 * Validate token
 * @param {string} token
 * @param {string} secret
 * @returns
 */
function validateToken(token, secret) {
    const [timestampStr, hash] = token.split('-');
    const timestamp = parseInt(timestampStr);
    const expectedHash = crypto_1.default.createHmac('sha256', secret)
        .update(timestamp.toString())
        .digest('hex');
    const threshold = 60 * 1000; // 1 minute expiration (adjust as needed)
    const expired = Date.now() - timestamp > threshold;
    return !expired && hash === expectedHash;
}
/**
 * CSRF Protection
 * @param {*} req
 * @param {*} res
 * @param {*} next
 * @returns
 */
function csrfProtection(secret) {
    return (req, res, next) => {
        /**
         * Initialize
        */
        req.csrfProtection = {
            generateToken: () => generateToken(secret)
        };
        /**
         * Get request handler
         */
        if (req.method === 'GET') {
            // Generate token on GET requests
            const token = generateToken(secret);
            req.csrfProtection.csrfToken = token;
            // Add token to response as cookie
            res.cookie('__node-auth:x-csrf-token', token, { httpOnly: true });
            // Optionally, add token to response as hidden form field (optional)
            res.locals.csrfToken = token;
        }
        /**
         * Validate token on POST|PUT|DELETE requests
         */
        if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
            const submittedToken = req.headers['x-csrf-token'];
            if (!submittedToken || !validateToken(submittedToken, secret)) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid request : csrf'
                });
            }
        }
        next();
    };
}
module.exports = { generateToken, csrfProtection };
