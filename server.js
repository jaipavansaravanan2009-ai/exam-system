console.log("Server file is running...");
require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Exam System API Running 🚀");
});

// Temporary storage
let exams = [];

// CREATE EXAM
app.post("/api/exams", (req, res) => {
  const { title, questions } = req.body;

  if (!title || !questions) {
    return res.status(400).json({ message: "Title and questions required" });
  }

  const newExam = {
    id: Date.now(),
    title,
    questions
  };

  exams.push(newExam);

  res.status(201).json({
    message: "Exam created successfully ✅",
    exam: newExam
  });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});