import dotenv from 'dotenv';
// This forces Node to look in the exact folder where index.js lives
dotenv.config({ path: './.env' }); 

import mongoose from 'mongoose';

console.log("Checking MONGO_URI:", process.env.MONGO_URI);

if (!process.env.MONGO_URI) {
    console.log("❌ Dotenv failed. Hardcoding for now...");
    process.env.MONGO_URI = "mongodb://127.0.0.1:27017/myDatabase";
}

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ Successfully connected to MongoDB"))
    .catch(err => console.error("❌ Connection error:", err));