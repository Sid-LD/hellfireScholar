const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const bodyParser = require("body-parser");

const app = express();
const PORT = 3000;
const SECRET_KEY = "your_super_secret_hellfire_key"; // In production, keep this in .env

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Mock Database (Replace with MongoDB/SQL in production)
const users = [];

// Helper: Generate JWT Token
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, email: user.email, name: user.name },
    SECRET_KEY,
    {
      expiresIn: "24h", // Token expires in 24 hours
    }
  );
};

// REGISTER Endpoint
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, course } = req.body;

    // Check if user exists
    if (users.find((u) => u.email === email)) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = {
      id: Date.now(),
      name,
      email,
      password: hashedPassword,
      course,
    };

    users.push(newUser);

    // Generate token
    const token = generateToken(newUser);

    res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        name: newUser.name,
        email: newUser.email,
        course: newUser.course,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Error registering user" });
  }
});

// LOGIN Endpoint
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = users.find((u) => u.email === email);
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate token
    const token = generateToken(user);

    res.json({
      message: "Login successful",
      token,
      user: { name: user.name, email: user.email, course: user.course },
    });
  } catch (error) {
    res.status(500).json({ message: "Error logging in" });
  }
});

// MIDDLEWARE: Verify Token (Protect Routes)
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "No token provided" });

  jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
    if (err)
      return res.status(500).json({ message: "Failed to authenticate token" });
    req.userId = decoded.id;
    next();
  });
};

// Example Protected Route
app.get("/api/dashboard-data", verifyToken, (req, res) => {
  res.json({
    message: "This is protected data",
    data: [
      /* your dashboard data */
    ],
  });
});

app.listen(PORT, () => {
  console.log(`🔥 Hellfire Server running on http://localhost:${PORT}`);
});
