import jwt from "jsonwebtoken";
import User from "../models/users.model.js";
import dotenv from "dotenv";

dotenv.config();

export const authenticateUser = async (req, res, next) => {
  try {
    const accessToken = req.cookies?.accessToken;

    if (!accessToken) {
      return res.status(401).json({
        success: false,
        message: "No access token",
      });
    }

    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);

    const userId = decoded.userId;

    const user = await User.findById(userId).select({ password: false });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not available",
      });
    }

    req.user = user;

    next();
  } catch (error) {
    if (
      error.name === "TokenExpiredError" ||
      error.name === "JsonWebTokenError" ||
      error.name === "NotBeforeError"
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired access token",
      });
    }
    next(error);
  }
};
