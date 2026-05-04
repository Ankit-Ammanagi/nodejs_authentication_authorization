import { NextFunction, Request, Response } from "express";

export default function requireRole(role: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const { user } = req as Request & { user?: any };

    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    if (!user.role || user.role !== role) {
      return res.status(403).json({ message: "Forbidden" });
    }

    next();
  };
}
