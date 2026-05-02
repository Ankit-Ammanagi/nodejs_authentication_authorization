import jwt from 'jsonwebtoken';

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