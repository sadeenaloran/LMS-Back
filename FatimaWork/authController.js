import UserModel from "../models/User.js";
import {
  registerSchema,
  loginSchema,
  changePasswordSchema, // Add this import
} from "../utils/validation.js";
import passport from "passport";
import logger from "../utils/logger.js";

const AuthController = {
  async register(req, res, next) {
    try {
      const {
        name,
        email,
        password,
        confirm_password,
        role = "student",
      } = req.body;

      const { error } = registerSchema.validate({
        name,
        email,
        password,
        confirm_password,
        role,
      });
      if (error) {
        logger.warn(
          `Registration validation failed: ${error.details[0].message}`
        );
        return res.status(400).json({
          success: false,
          message: error.details[0].message,
        });
      }

      const existingUser = await UserModel.findByEmail(email);
      if (existingUser) {
        logger.warn(`Duplicate registration attempt: ${email}`);
        return res.status(409).json({
          success: false,
          message: "Email already in use",
        });
      }

      const user = await UserModel.create({ name, email, password, role });
      const token = UserModel.generateToken(user.id, user.role);

      res.status(201).json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      logger.error(`Registration error: ${error.message}`);
      next(error);
    }
  },

  async login(req, res, next) {
    try {
      const { email, password } = req.body;

      const { error } = loginSchema.validate({ email, password });
      if (error) {
        return res.status(400).json({
          success: false,
          message: error.details[0].message,
        });
      }

      const user = await UserModel.findByEmail(email);
      if (!user) {
        logger.warn(`Login attempt for unknown email: ${email}`);
        return res.status(401).json({
          success: false,
          message: "Invalid credentials",
        });
      }

      const isMatch = await UserModel.verifyPassword(
        password,
        user.password_hash
      );
      if (!isMatch) {
        logger.warn(`Failed login attempt for: ${email}`);
        return res.status(401).json({
          success: false,
          message: "Invalid credentials",
        });
      }

      const token = UserModel.generateToken(user.id, user.role);
      await UserModel.updateLastLogin(user.id);

      res.json({
        success: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
      });
    } catch (error) {
      logger.error(`Login error: ${error.message}`);
      next(error);
    }
  },
  async changePassword(req, res, next) {
    try {
      const { currentPassword, newPassword, confirmNewPassword } = req.body;
      const userId = req.user.id;

      // Validate input
      const { error } = changePasswordSchema.validate({
        currentPassword,
        newPassword,
        confirmNewPassword,
      });

      if (error) {
        logger.warn(
          `Password change validation failed: ${error.details[0].message}`
        );
        return res.status(400).json({
          success: false,
          message: error.details[0].message,
        });
      }

      // Get user with password hash
      const user = await UserModel.findWithPassword(userId);
      if (!user) {
        logger.warn(`Password change attempt for non-existent user: ${userId}`);
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      // Verify current password
      const isMatch = await UserModel.verifyPassword(
        currentPassword,
        user.password_hash
      );

      if (!isMatch) {
        logger.warn(`Incorrect current password attempt for user: ${userId}`);
        return res.status(401).json({
          success: false,
          message: "Current password is incorrect",
        });
      }

      // Update password
      await UserModel.updatePassword(userId, newPassword);
      logger.info(`Password successfully changed for user: ${userId}`);

      res.json({
        success: true,
        message: "Password updated successfully",
      });
    } catch (error) {
      logger.error(`Password change error: ${error.message}`);
      next(error);
    }
  },
  googleAuth: passport.authenticate("google", {
    scope: ["profile", "email"],
    session: false,
  }),
  googleAuthCallback: async (req, res) => {
    try {
      const token = UserModel.generateToken(req.user.id, req.user.role);

      res.redirect(
        `${process.env.CORS_ORIGIN}/auth/success?` +
          `token=${token}&` +
          `id=${req.user.id}&` +
          `name=${encodeURIComponent(req.user.name)}&` +
          `email=${encodeURIComponent(req.user.email)}&` +
          `avatar=${encodeURIComponent(req.user.avatar || "")}&` +
          `role=${req.user.role}`
      );
    } catch (error) {
      logger.error(`Google callback error: ${error.message}`);
      res.redirect(`${process.env.CORS_ORIGIN}/login?error=oauth_failed`);
    }
  },

  async getMe(req, res, next) {
    try {
      const user = await UserModel.findById(req.user.id);

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }

      res.json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          avatar: user.avatar, // Include avatar in response
        },
      });
    } catch (error) {
      next(error);
    }
  },
  async logout(req, res, next) {
    try {
      res.status(200).json({
        success: true,
        message: "Logged out successfully",
      });
    } catch (error) {
      logger.error(`Logout error: ${error.message}`);
      next(error);
    }
  },
};

export default AuthController;
