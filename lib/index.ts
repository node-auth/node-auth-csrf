import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';

interface CSRFProtectionOptions {
    secret: string;
    tokenExpiration?: number; // Token expiration time in milliseconds (default: 1 minute)
}

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
 * Generate CSRF token
 * @param {string} secret 
 * @returns {string} token
 */
function generateToken(secret: string): string {
    const randomBytes = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now().toString();
    const hash = crypto.createHmac('sha256', secret)
        .update(randomBytes + timestamp)
        .digest('hex');
    return `${timestamp}-${hash}`;
}

/**
 * Validate CSRF token
 * @param {string} token 
 * @param {string} secret 
 * @param {number} expiration 
 * @returns {boolean} validity
 */
function validateToken(token: string, secret: string, expiration: number): boolean {
    const [timestampStr, hash] = token.split('-');
    const timestamp = parseInt(timestampStr);
    if (isNaN(timestamp)) return false;
    
    const currentTime = Date.now();
    if (currentTime - timestamp > expiration) return false;

    const expectedHash = crypto.createHmac('sha256', secret)
        .update(token)
        .digest('hex');
    return hash === expectedHash;
}

/**
 * CSRF Protection middleware
 * @param {CSRFProtectionOptions} options 
 * @returns {RequestHandler} middleware
 */
function csrfProtection(options: CSRFProtectionOptions) {
    const { secret, tokenExpiration = 60 * 1000 } = options;

    return (req: Request, res: Response, next: NextFunction) => {
        /**
         * Initialize csrfProtection object in request
         */
        req.csrfProtection = {
            generateToken: () => generateToken(secret)
        };

        /**
         * Generate token on GET requests
         */
        if (req.method === 'GET') {
            const token = generateToken(secret);
            req.csrfProtection.csrfToken = token;
            res.cookie('__node-auth:x-csrf-token', token, { httpOnly: true, secure: true });
            res.locals.csrfToken = token; // Optionally, add token to response as hidden form field (optional)
        }

        /**
         * Validate token on POST|PUT|DELETE requests
         */
        if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE') {
            const submittedToken = req.headers['x-csrf-token'] as string;
            if (!submittedToken || !validateToken(submittedToken, secret, tokenExpiration)) {
                return res.status(403).json({
                    success: false,
                    message: 'Invalid request: CSRF token validation failed'
                });
            }
        }

        next();
    };
}

export { generateToken, csrfProtection };