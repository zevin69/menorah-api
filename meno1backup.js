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
import session from "express-session";
import articleRoute from "./routes/articleRoute.js";

dotenv.config({ path: "./.env" });

if (!process.env.MONGO_URI) {
    console.error("❌ MONGO_URI is undefined. Check your .env file.");
    process.exit(1);
}

console.log("✅ MONGO_URI Loaded:", process.env.MONGO_URI);

const app = express();

// ✅ Enable CORS
app.use(cors({
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type"]
}));

// ✅ Middleware Setup (SESSION FIRST)
app.use(session({
    secret: process.env.JWT_SECRET || "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24, 
    }
}));

// ✅ Initialize Passport **AFTER** session setup
app.use(passport.initialize());
app.use(passport.session());

// ✅ Parse JSON and URL-encoded requests
app.use(express.json());
app.use(express.urlencoded({ extended: true }));



// ✅ PostgreSQL Connection (Updated for Supabase)
const { Pool } = pkg;

const pool = new Pool({
    connectionString: 'postgresql://postgres:027267@Appu@localhost:5432/menorah_users',
    ssl: false,
});

// ✅ PostgreSQL Connection Test
pool.query("SELECT NOW()", (err, res) => {
    if (err) {
        console.error("❌ PostgreSQL connection error:", err);
    } else {
        console.log("✅ PostgreSQL connected at:", res.rows[0].now);
    }
});

// ✅ MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB connected!"))
    .catch(err => console.log("❌ MongoDB connection error:", err));

// ✅ Routes
app.use("/articles", articleRoute);

// ✅ Nodemailer Setup
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// ✅ Signup Route
app.post("/signup", async (req, res) => {
    const { email, password } = req.body;
    try {
        const userCheck = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ message: "Email already registered" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hashedPassword]);

        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });

        const PORT = process.env.PORT || 5050;


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

// ✅ Email Verification Route
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

// ✅ Login Route
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        const userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userResult.rows.length === 0) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const user = userResult.rows[0];

        if (!user.verified) {
            return res.status(400).json({ message: "Please verify your email first" });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: "Invalid email or password" });
        }

        const token = jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "24h" });

        res.json({ message: "Login successful", token });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
});

// ✅ Google Auth Strategy
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

// ✅ Google Auth Routes
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));

app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
        res.send("Google login successful!");
    }
);

// Export pool properly
export { pool };

// ✅ Start Server
const PORT = process.env.PORT || 5050;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
