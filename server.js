require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");

// Firebase setup
const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

const app = express();

app.use(cors());
app.use(express.json());

console.log("Server file is running...");

/* ==============================
   🔐 ADD verifyAdmin RIGHT HERE
   ============================== */

function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "Access denied 🚫" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = verified;
    next();
  } catch (err) {
    return res.status(400).json({ message: "Invalid token ❌" });
  }
}

app.get("/", (req, res) => {
  res.send("Exam System API Running 🚀");
});

// Temporary storage
let exams = [];

// CREATE EXAM
app.post("/api/exams", verifyAdmin, async (req, res) => {
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

// DELETE EXAM (Firebase)
app.delete("/api/exams/:id", verifyAdmin, async (req, res) => {
  const examId = req.params.id;

  try {
    const examRef = db.collection("exams").doc(examId);

    const doc = await examRef.get();

    if (!doc.exists) {
      return res.status(404).json({ message: "Exam not found ❌" });
    }

    await examRef.delete();

    res.json({ message: "Exam deleted successfully 🗑️" });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// 🎓 PUBLIC ROUTES FOR STUDENTS
// ==========================================

// 1. Get all exams (without answers)
app.get("/api/public/exams", async (req, res) => {
  try {
    const snapshot = await db.collection("exams").get();
    const exams = snapshot.docs.map(doc => ({
      id: doc.id,
      title: doc.data().title,
      questionCount: doc.data().questions ? doc.data().questions.length : 0
    }));
    res.json(exams);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. Get a specific exam to attempt
app.get("/api/public/exams/:id", async (req, res) => {
  try {
    const doc = await db.collection("exams").doc(req.params.id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Exam not found ❌" });
    }
    res.json({ id: doc.id, ...doc.data() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// 📊 RESULTS & LEADERBOARD ROUTES
// ==========================================

// 1. Save Student Result (Public)
app.post("/api/public/submit", async (req, res) => {
  try {
    const resultData = req.body;
    resultData.submittedAt = new Date(); // Adds timestamp
    
    // Automatically creates a "results" collection in Firebase!
    await db.collection("results").add(resultData); 
    res.status(201).json({ message: "Result saved successfully ✅" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. Get All Results (Protected - Admin Only)
app.get("/api/results", verifyAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection("results").get();
    const results = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 5000;

// UPDATE EXAM
app.put("/api/exams/:id", verifyAdmin, async (req, res) => {
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

// ADMIN LOGIN
app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const snapshot = await db
      .collection("admins")
      .where("email", "==", email)
      .get();

    if (snapshot.empty) {
      return res.status(401).json({ message: "Invalid email ❌" });
    }

    const adminDoc = snapshot.docs[0];
    const admin = adminDoc.data();

    const isMatch = await bcrypt.compare(password, admin.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Wrong password ❌" });
    }

    const token = jwt.sign(
      { id: adminDoc.id, email: admin.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ message: "Login successful ✅", token });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }

  // ADD QUESTION TO EXAM
app.post("/api/exams/:id/questions", verifyAdmin, async (req, res) => {
  const examId = req.params.id;
  const { question, options, correctAnswer } = req.body;

  try {
    const examRef = db.collection("exams").doc(examId);
    const doc = await examRef.get();

    if (!doc.exists) {
      return res.status(404).json({ message: "Exam not found ❌" });
    }

    const examData = doc.data();

    const updatedQuestions = [
      ...(examData.questions || []),
      { question, options, correctAnswer }
    ];

    await examRef.update({
      questions: updatedQuestions
    });

    res.json({ message: "Question added successfully ✅" });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

});