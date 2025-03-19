const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");
const bodyParser = require("body-parser");
const { v4: uuidv4 } = require("uuid");
const winston = require("winston");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const ACCESS_SECRET = process.env.ACCESS_SECRET || "SECRET1";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "SECRET2";

// Configure winston logging
const logger = winston.createLogger({
  level: "info",
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
          return `${timestamp} ${level}: ${message}`;
        })
      ),
    }),
    new winston.transports.File({
      filename: "logs/app.log",
      level: "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
    }),
  ],
});

app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(bodyParser.json());

// Simulated user database
const users = [];
const refreshTokens = [];

function generateAccessToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    ACCESS_SECRET,
    { expiresIn: "15m" }
  );
}

function generateRefreshToken(user) {
  const refreshToken = jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    REFRESH_SECRET,
    { expiresIn: "7d" }
  );
  refreshTokens.push(refreshToken);
  return refreshToken;
}

function registerUser(req, res) {
  const { email, name, password } = req.body;
  const existingUser = users.find(
    (user) => user.email === email || user.name === name
  );
  if (existingUser) {
    logger.warn(
      `Attempted to register existing user with email/name: ${email || name}`
    );
    return res.status(409).json({ message: "User already exists" });
  }
  bcrypt.hash(password, 10).then((hashedPassword) => {
    const newUser = {
      id: uuidv4(),
      email,
      name,
      password: hashedPassword,
      creationDate: new Date().toISOString(),
      lastLogin: new Date().toISOString(),
    };
    users.push(newUser);
    logger.info(`User registered successfully: ${email || name}`);
    res
      .status(201)
      .json({ user: newUser, message: "User registered successfully" });
  });
}

function loginUser(req, res) {
  const { identifier, password } = req.body;

  // Find user by either name or email
  const user = users.find(
    (user) => user.email === identifier || user.name === identifier
  );

  if (!user) {
    logger.warn(`Invalid login attempt for identifier: ${identifier}`);
    return res.status(400).json({ message: "Invalid identifier or password" });
  }

  bcrypt.compare(password, user.password).then((isMatch) => {
    if (!isMatch) {
      logger.warn(`Invalid login attempt for identifier: ${identifier}`);
      return res
        .status(400)
        .json({ message: "Invalid identifier or password" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    // Send access token in response, store refresh token in HttpOnly cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true, // Ensure cookies are sent over HTTPS
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      sameSite: "Strict", // Mitigate CSRF attacks
    });

    logger.info(`User logged in successfully: ${user.email || user.name}`);
    res.json({ user, accessToken });
  });
}

function refreshToken(req, res) {
  const refreshToken = req.cookies.refreshToken; // Read the refresh token from the HTTP-only cookie
  if (!refreshToken) {
    logger.warn("Refresh token missing in request");
    return res.status(403).json({ message: "Refresh token is missing" });
  }
  if (!refreshTokens.includes(refreshToken)) {
    logger.warn("Invalid refresh token attempt");
    return res.status(403).json({ message: "Forbidden" });
  }
  jwt.verify(refreshToken, REFRESH_SECRET, (err, user) => {
    if (err) {
      logger.error("Failed to verify refresh token");
      return res.status(403).json({ message: "Forbidden" });
    }
    const newAccessToken = generateAccessToken(user);
    logger.info(
      `New access token generated for user: ${user.email || user.name}`
    );
    res.json({ accessToken: newAccessToken });
  });
}

function authenticate(req, res, next) {
  const token = req.headers.authorization;
  if (!token) {
    logger.warn("Access denied: No token provided");
    return res.status(401).json({ message: "Access denied" });
  }

  try {
    const decoded = jwt.verify(token.split(" ")[1], ACCESS_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    logger.error("Invalid token provided");
    res.status(401).json({ message: "Invalid token" });
  }
}

function logoutUser(req, res) {
  // Extract token from Authorization header
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];
  if (!token) {
    logger.warn("No token provided for logout");
    return res.status(401).json({ message: "Access denied" });
  }

  // Verify the JWT token
  jwt.verify(token, ACCESS_SECRET, (err, decoded) => {
    if (err) {
      logger.error("Invalid token provided for logout");
      return res.status(403).json({ message: "Invalid token" });
    }

    // Get user id or email from the decoded token
    const { id, email } = decoded;

    // Find the corresponding refresh token for the user
    const refreshTokenIndex = refreshTokens.findIndex(
      (rt) => jwt.verify(rt, REFRESH_SECRET).id === id
    );

    // If a corresponding refresh token exists, invalidate it
    if (refreshTokenIndex !== -1) {
      refreshTokens.splice(refreshTokenIndex, 1);
      logger.info(
        `User with email ${email} logged out, refresh token invalidated`
      );
    } else {
      logger.warn(`No valid refresh token found for user with email ${email}`);
    }

    res.json({ message: "Logged out" });
  });
}

function protectedRoute(req, res) {
  res.json({
    message: `Hello, ${req.user.name}! This is a protected route.`,
  });
}

app.post("/register", registerUser);
app.post("/login", loginUser);
app.post("/refresh", refreshToken);
app.post("/logout", logoutUser);
app.get("/protected", authenticate, protectedRoute);

app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
