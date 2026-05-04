import { Request, Response, Router } from "express";
import { requireAuth } from "../middleware/requireAuth";

const router = Router();

router.get("/profile", requireAuth, async (req: Request, res: Response) => {
  const authReq = req as Request & { user?: any };

  return res.json({
    user: authReq.user,
  });
});

export default router;
