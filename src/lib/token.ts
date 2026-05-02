import jwt from 'jsonwebtoken';
import crypto from 'crypto'

export function generateToken(userId: string, role: 'user' | 'admin', tokenVersion: number) {
    const payload = {
        userId,
        role,
        tokenVersion
    };

    const secret = process.env.JWT_ACCESS_SECRET;
    if (!secret) {
        throw new Error("JWT_ACCESS_SECRET is not set in environment variables");
    }

    return jwt.sign(payload, secret, { expiresIn: '30m' });
}

export function generateRefreshToken(userId: string, tokenVersion: number) {
    const payload = {
        userId,
        tokenVersion
    };

    const secret = process.env.JWT_REFRESH_SECRET;
    if (!secret) {
        throw new Error("JWT_REFRESH_SECRET is not set in environment variables");
    }

    return jwt.sign(payload, secret, { expiresIn: '7d' });
}

export async function verifyRefreshToken(token: string) {
    const secret = process.env.JWT_REFRESH_SECRET;
    if (!secret) {
        throw new Error("JWT_ACCESS_SECRET is not set in environment variables");
    }

    return jwt.verify(token, secret) as {
        userId: string,
        tokenVersion: number,
    }
}

export function getHashedToken(){
    const rawToken = crypto.randomBytes(32).toString("hex");
    return crypto.createHash("sha256").update(rawToken).digest("hex");
}