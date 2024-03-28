import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

/**
 * I created this csrf protection based on my R&D
 * you can suggest an improvement for this
 */

declare global {
    namespace Express {
        interface Request {
            csrfProtection: {
                generateToken?: () => string;
                csrfToken?: string;
            };
        }
    }
}

/**
 * Generate csrf token
 * @returns token
 */
function generateToken(secret: string): string {
    const timestamp = Date.now().toString();
    const hash = crypto.createHmac('sha256', secret)
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
function validateToken(token: string, secret: string) {
    const [timestampStr, hash] = token.split('-');
    const timestamp = parseInt(timestampStr);
    const expectedHash = crypto.createHmac('sha256', secret)
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
function csrfProtection(secret: string) {
    return (req: Request, res: Response, next: NextFunction) => {
        /**
         * Initialize
        */
        req.csrfProtection = {
            generateToken: () => generateToken(secret)
        }

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
            const submittedToken = req.headers['x-csrf-token'] as string;
            if (!submittedToken || !validateToken(submittedToken, secret)) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid request : csrf'
                });
            }
        }
        next();
    }
}

module.exports = { generateToken, csrfProtection };