import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../models/user.model";
import { comparePasswords, hashPassword } from "../lib/hash";
import jwt from "jsonwebtoken";
import { sendEmail } from "../lib/email";
import { generateRefreshToken, generateToken } from "../lib/token";

function getAppUrl() {
  return process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
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
      sameSite: "strict",
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
