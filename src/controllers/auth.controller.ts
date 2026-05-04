import { Request, Response } from "express";
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
  resetPasswordSchema,
} from "./auth.schema";
import { User } from "../models/user.model";
import { comparePasswords, hashPassword } from "../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../lib/email";
import {
  generateRefreshToken,
  generateToken,
  getHashedToken,
  verifyRefreshToken,
} from "../lib/token";
import { OAuth2Client } from "google-auth-library";
import crypto from "crypto";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
}

function getGoogleClient() {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;

  if (!clientId || !clientSecret || !redirectUri) {
    throw new Error("Google OAuth environment variables are not set");
  }

  return new OAuth2Client({
    clientId,
    clientSecret,
    redirectUri,
  });
}

export async function registerHandler(req: Request, res: Response) {
  try {
    const result = registerSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Ivalid data!",
        error: result.error.flatten(),
      });
    }

    const { email, password, name } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({ message: "Email already in use" });
    }

    const passwordHash = await hashPassword(password);

    const newUser = await User.create({
      name,
      email: normalizedEmail,
      passwordHash,
      isEmailVerified: false,
      twoFactorEnabled: false,
    });

    const verifyToken = jwt.sign(
      { sub: newUser._id },
      process.env.JWT_ACCESS_SECRET!,
      { expiresIn: "1d" },
    );

    const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      "Verify your email",
      `<p>Click the link below to verify your email:</p><a href="${verifyUrl}">click</a>`,
    );

    return res.status(201).json({
      message:
        "User registered successfully. Please check your email to verify your account.",
      user: {
        id: newUser._id,
        email: newUser.email,
        name: newUser.name,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const { token } = req.query;

  if (!token || typeof token !== "string") {
    return res.status(400).json({ message: "Invalid token" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      sub: string;
    };

    const user = await User.findById(decoded.sub);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isEmailVerified) {
      return res.status(400).json({ message: "Email already verified" });
    }

    user.isEmailVerified = true;

    await user.save();

    return res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("Email verification error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function loginHandler(req: Request, res: Response) {
  try {
    const result = loginSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data!",
        error: result.error.flatten(),
      });
    }

    const { email, password } = result.data;
    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json({ message: "Please verify your email before logging in" });
    }

    const isPasswordValid = await comparePasswords(password, user.passwordHash);

    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const accessToken = generateToken(
      user._id.toString(),
      user.role,
      user.tokenVersion,
    );

    const refreshToken = generateRefreshToken(
      user._id.toString(),
      user.tokenVersion,
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: "Login successful",
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function refreshHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken;

    if (!token) {
      return res.status(401).json({ message: "No refresh token provided" });
    }

    const { userId, tokenVersion } = await verifyRefreshToken(token);

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.tokenVersion !== tokenVersion) {
      return res.status(401).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = generateToken(
      user._id.toString(),
      user.role,
      user.tokenVersion,
    );

    const newRefreshToken = generateRefreshToken(
      user._id.toString(),
      user.tokenVersion,
    );

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
        twofactorEnabled: user.twoFactorEnabled,
      },
    });
  } catch (error) {
    console.error("Token refresh error:", error);
    return res.status(401).json({ message: "Invalid refresh token" });
  }
}

export async function logoutHandler(req: Request, res: Response) {
  try {
    const token = req.cookies?.refreshToken;

    if (!token) {
      return res.status(400).json({ message: "No refresh token provided" });
    }

    res.clearCookie("refreshToken", {
      path: "/",
    });

    return res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function forgotPasswordHandler(req: Request, res: Response) {
  try {
    const result = forgotPasswordSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data",
        error: result.error.flatten(),
      });
    }

    const { email } = result.data;

    const normalizedEmail = email.toLowerCase().trim();

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message:
          "If an account with this email exists, we will send you reset link",
      });
    }

    const tokenHash = getHashedToken();

    user.resetPasswordToken = tokenHash;
    user.resetPasswordExpires = new Date(Date.now() + 5 * 60 * 1000);

    await user.save();

    const resetUrl = `${getAppUrl()}/auth/reset-password?token=${tokenHash}`;

    await sendEmail(
      user.email,
      "Reset your password",
      `<p>You requested password reset</p>
            <p>Click on the below link to reset yout password</p>
            <p><a href=${resetUrl}>link</a></p>
            `,
    );

    return res.json({
      message:
        "If an account with this email exists, we will send you reset link",
    });
  } catch (error) {
    console.error("Forgot password error: ", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function resetPasswordHandler(req: Request, res: Response) {
  try {
    const result = resetPasswordSchema.safeParse(req.body);

    if (!result.success) {
      return res.status(400).json({
        message: "Invalid data",
        error: result.error.flatten(),
      });
    }

    const { email, token, password } = result.data;

    const user = await User.findOne({
      email: email,
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Invalid date or expired token",
      });
    }

    const newPasswordHash = await hashPassword(password);

    user.passwordHash = newPasswordHash;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    user.tokenVersion = user.tokenVersion + 1;

    await user.save();

    return res.json({
      message: "Password reset successfully!",
    });
  } catch (error) {
    console.error("Reset Password error: ", error);

    return res.status(500).json({
      message: "Internal server error",
    });
  }
}

export async function googleAuthStartHandler(req: Request, res: Response) {
  try {
    const client = getGoogleClient();

    const url = client.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["openid", "email", "profile"],
    });

    return res.redirect(url);
  } catch (error) {
    console.error("Google Auth Start error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}

export async function googleAuthCallbackHandler(req: Request, res: Response) {
  const code = req.query.code as string;

  if (!code) {
    return res.status(400).json({ message: "No code provided" });
  }

  try {
    const client = getGoogleClient();

    const { tokens } = await client.getToken(code);

    if (!tokens.id_token) {
      return res
        .status(400)
        .json({ message: "No id token received from Google" });
    }

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID as string,
    });

    const payload = ticket.getPayload();

    const email = payload?.email;
    const emailVerified = payload?.email_verified;

    if (!email || !emailVerified) {
      return res.status(400).json({ message: "Email not verified by Google" });
    }

    const normalizedEmail = email.toLocaleLowerCase().trim();

    let user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      const randomPassword = crypto.randomBytes(16).toString("hex");
      const passwordHash = await hashPassword(randomPassword);

      user = await User.create({
        name: payload?.name,
        email: normalizedEmail,
        passwordHash,
        isEmailVerified: true,
        twoFactorEnabled: false,
      });
    } else if (!user.isEmailVerified) {
      user.isEmailVerified = true;
      await user.save();
    }

    const accessToken = generateToken(
      user._id.toString(),
      user.role as "user" | "admin",
      user.tokenVersion,
    );

    const refreshToken = generateRefreshToken(
      user._id.toString(),
      user.tokenVersion,
    );

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    return res.status(200).json({
      message: "Login successful",
      accessToken,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role,
        isEmailVerified: user.isEmailVerified,
      },
    });
  } catch (error) {
    console.error("Google Auth Callback error:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
}
