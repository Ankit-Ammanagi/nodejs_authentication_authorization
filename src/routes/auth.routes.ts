import { Router } from "express";
import {
  loginHandler,
  registerHandler,
  verifyEmailHandler,
} from "../controllers/auth.controller";

const router = Router();

router.post("/register", registerHandler);
router.post("/login", loginHandler);
router.get("/verify-email", verifyEmailHandler);

export default router;
