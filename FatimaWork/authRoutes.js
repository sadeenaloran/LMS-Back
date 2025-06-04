import { Router } from "express";
import AuthController from "../controllers/authController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = Router();

// Google OAuth
router.get("/google", AuthController.googleAuth);
router.get("/google/callback", AuthController.googleAuthCallback);

// Local Auth
router.post("/register", AuthController.register);
router.post("/login", AuthController.login);
router.post("/logout", AuthController.logout);
router.put("/change-password", authenticate, AuthController.changePassword);
router.get("/me", authenticate, AuthController.getMe);

export default router;
