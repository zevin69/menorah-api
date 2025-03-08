import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import articleRoute from "./routes/articleRoute.js";  // ✅ Correct import

dotenv.config({ path: "./.env" });

if (!process.env.MONGO_URI) {
    console.error("❌ MONGO_URI is undefined. Check your .env file.");
    process.exit(1);
}

console.log("✅ MONGO_URI Loaded:", process.env.MONGO_URI);

const app = express();
app.use(express.json());  // Middleware to parse JSON

// ✅ Enable CORS
app.use(cors({
    origin: "*", // Allow requests from any origin (change this for security)
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type"]
}));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB connected!"))
    .catch(err => console.log("❌ MongoDB connection error:", err));

// Use Routes
app.use("/articles", articleRoute);  // ✅ Use articles as the API path

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
