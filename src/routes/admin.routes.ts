import { Request, Response, Router } from "express";
import requireRole from "../middleware/requireRole";
import { requireAuth } from "../middleware/requireAuth";
import { User } from "../models/user.model";

const router = Router();

router.get(
  "/users",
  requireAuth,
  requireRole("admin"),
  async (req: Request, res: Response) => {
    try {
      const users = await User.find(
        {},
        {
          name: 1,
          email: 1,
          role: 1,
          isEmailVerified: 1,
          createdAt: 1,
        },
      ).sort({ createdAt: -1 });

      const result = users.map((u) => ({
        id: u._id,
        name: u.name,
        email: u.email,
        role: u.role,
        isEmailVerified: u.isEmailVerified,
        createdAt: u.createdAt,
      }));

      return res.json({
        users: result,
      });
    } catch (error) {
        console.error("Error fetching users:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
  },
);

export default router;
