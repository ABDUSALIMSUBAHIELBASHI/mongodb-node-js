import express from "express";
import mongoose from "mongoose";

import namesRouter from "./routes/names.js";
import registerRouter from "./routes/register.js"; 
import dotenv from 'dotenv'


dotenv.config();
const app = express();
const PORT = process.env.port;


app.use(express.json());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// Home route
app.get("/", (req, res) => {
  res.send("<h1>Welcome to the Names API</h1>");
});


app.use("/names", namesRouter);
app.use("/register", registerRouter); 


app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
