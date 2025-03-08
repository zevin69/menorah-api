import mongoose from "mongoose";

const articleSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: String, required: true },
    category: { type: String, enum: ["Campus News", "Events", "Interviews"], required: true },
    image: { type: String },  // Store image URLs if needed
    createdAt: { type: Date, default: Date.now }
});

const Article = mongoose.model("Article", articleSchema);

export default Article;
