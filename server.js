const admin = require("firebase-admin");

const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

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
app.post("/api/exams", async (req, res) => {
  const { title, questions } = req.body;

  if (!title || !questions) {
    return res.status(400).json({ message: "Title and questions required" });
  }

  try {
    const docRef = await db.collection("exams").add({
      title,
      questions,
      createdAt: new Date()
    });

    res.status(201).json({
      message: "Exam saved to Firebase ✅",
      id: docRef.id
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/exams", async (req, res) => {
  try {
    const snapshot = await db.collection("exams").get();

    const exams = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(exams);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// DELETE EXAM
app.delete("/api/exams/:id", (req, res) => {
  const examId = parseInt(req.params.id);

  const examIndex = exams.findIndex(exam => exam.id === examId);

  if (examIndex === -1) {
    return res.status(404).json({ message: "Exam not found ❌" });
  }

  exams.splice(examIndex, 1);

  res.json({ message: "Exam deleted successfully 🗑️" });
});

const PORT = process.env.PORT || 5000;

// UPDATE EXAM
app.put("/api/exams/:id", async (req, res) => {
  const examId = req.params.id;
  const { title, questions } = req.body;

  if (!title && !questions) {
    return res.status(400).json({ message: "Nothing to update ❌" });
  }

  try {
    const examRef = db.collection("exams").doc(examId);

    await examRef.update({
      ...(title && { title }),
      ...(questions && { questions }),
      updatedAt: new Date()
    });

    res.json({ message: "Exam updated successfully 🔄" });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});