import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.model";

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const authHeaser = req.headers.authorization;

  if (!authHeaser || !authHeaser.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeaser.split(" ")[1];

  try {
    const payload = verifyAccessToken(token);

    const user = await User.findById(payload.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Invalid token" });
    }

    const authReq = req as Request & { user?: any };

    authReq.user = {
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
    };

    next();
  } catch (error) {
    console.error("Auth error:", error);
    return res.status(401).json({ message: "Unauthorized" });
  }
}
