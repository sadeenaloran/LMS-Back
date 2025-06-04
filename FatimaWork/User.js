import { query } from "../config/db.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const UserModel = {
  async create({
    name,
    email,
    password,
    role = "student",
    google_id = null,
    avatar = null,
  }) {
    const hashedPassword = password
      ? await bcrypt.hash(password, parseInt(process.env.BCRYPT_SALT_ROUNDS))
      : null;

    const { rows } = await query(
      `INSERT INTO users 
       (name, email, password_hash, role, google_id, avatar, is_active) 
       VALUES ($1, $2, $3, $4, $5, $6, true)
       RETURNING id, name, email, role, avatar, created_at`,
      [name, email, hashedPassword, role, google_id, avatar]
    );
    return rows[0];
  },

  async findByEmail(email) {
    const { rows } = await query(
      "SELECT id, name, email, password_hash, role, avatar FROM users WHERE email = $1",
      [email]
    );
    return rows[0];
  },

  async findById(id) {
    const { rows } = await query(
      "SELECT id, name, email, role, avatar FROM users WHERE id = $1",
      [id]
    );
    return rows[0];
  },

  async findWithPassword(id) {
    const { rows } = await query(
      "SELECT id, password_hash FROM users WHERE id = $1",
      [id]
    );
    return rows[0];
  },

  async findByGoogleId(googleId) {
    const { rows } = await query(
      "SELECT id, name, email, role, avatar FROM users WHERE google_id = $1",
      [googleId]
    );
    return rows[0];
  },

  async verifyPassword(candidatePassword, hashedPassword) {
    return await bcrypt.compare(candidatePassword, hashedPassword);
  },

  async updatePassword(userId, newPassword) {
    const hashedPassword = await bcrypt.hash(
      newPassword,
      parseInt(process.env.BCRYPT_SALT_ROUNDS)
    );

    await query(
      "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
      [hashedPassword, userId]
    );
  },

  async updateLastLogin(userId) {
    await query("UPDATE users SET last_login = NOW() WHERE id = $1", [userId]);
  },

  generateToken(userId, role, expiresIn = "7d") {
    return jwt.sign({ id: userId, role }, process.env.JWT_SECRET, {
      expiresIn,
    });
  },
};

export default UserModel;
