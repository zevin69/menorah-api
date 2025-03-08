import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import articleRoute from "./routes/articleRoute.js"; // ✅ Correct import

dotenv.config({ path: "./.env" });

if (!process.env.MONGO_URI) {
    console.error("❌ MONGO_URI is undefined. Check your .env file.");
    process.exit(1);
}

console.log("✅ MONGO_URI Loaded:", process.env.MONGO_URI);

const app = express();
app.use(express.json()); // Middleware to parse JSON

// ✅ Enable CORS
app.use(cors({
    origin: "*", // Allow requests from any origin (change this for security)
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type"]
}));

// PostgreSQL
const { Pool } = pkg;
const pool = new Pool({
    user: "postgres",
    host: "localhost",
    database: "menorah_users",
    password: "027267@Appu",
    port: 5432,
});

export default pool;

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB connected!"))
    .catch(err => console.log("❌ MongoDB connection error:", err));

// Use Routes
app.use("/articles", articleRoute); // ✅ Use articles as the API path

// Change the PORT to avoid conflicts
const PORT = process.env.PORT || 5050; // Changed to 5050 to avoid conflicts

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

// 🛑 Removed the second `app.listen(PORT, ... )` call

// Nodemailer setup (for email verification)
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Sign Up Route
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user already exists
        const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ message: "Email already registered" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into DB
        const newUser = await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hashedPassword]
        );

        // Create verification token
        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });

        // Send verification email
        const verificationLink = `http://localhost:${PORT}/verify-email?token=${token}`;
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Verify Your Email",
            text: `Click this link to verify your email: ${verificationLink}`,
        });

        res.status(201).json({ message: "User registered! Check your email to verify." });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Email Verification Route
app.get("/verify-email", async (req, res) => {
    const { token } = req.query;

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await pool.query("UPDATE users SET verified = TRUE WHERE email = $1", [decoded.email]);
        res.send("Email verified! You can now log in.");
    } catch (error) {
        res.status(400).send("Invalid or expired token.");
    }
});

// 🛑 Removed the duplicate `app.listen(PORT, () => {...})`

// Login Route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if user exists
        const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const user = userResult.rows[0];

        // Check if email is verified
        if (!user.verified) {
            return res.status(400).json({ message: "Please verify your email first" });
        }

        // Compare password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        // Generate JWT Token
        const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "24h" });

        res.json({ message: "Login successful", token });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// Google Auth
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(passport.initialize());
app.use(passport.session());

// Google Auth Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    const email = profile.emails[0].value;

    try {
        const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (userCheck.rows.length === 0) {
            await pool.query("INSERT INTO users (email, verified) VALUES ($1, TRUE)", [email]);
        }

        return done(null, profile);
    } catch (error) {
        return done(error, null);
    }
}));

app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
        res.send("Google login successful!");
    }
);
