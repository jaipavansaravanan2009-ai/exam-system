require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");

// 1. Firebase setup
const serviceAccount = JSON.parse(process.env.FIREBASE_KEY);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});
const db = admin.firestore();

const app = express();
app.use(cors());
app.use(express.json());

console.log("Server is starting up... 🚀");

// 2. Admin Verification Middleware
function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Access denied 🚫" });

  const token = authHeader.split(" ")[1];
  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = verified;
    next();
  } catch (err) {
    return res.status(400).json({ message: "Invalid token ❌" });
  }
}

// ==========================================
// 🔑 ADMIN AUTH ROUTES
// ==========================================

app.post("/api/admin/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const snapshot = await db.collection("admins").where("email", "==", email).get();
    if (snapshot.empty) return res.status(401).json({ message: "Invalid email ❌" });

    const adminDoc = snapshot.docs[0];
    const adminData = adminDoc.data();
    const isMatch = await bcrypt.compare(password, adminData.password);

    if (!isMatch) return res.status(401).json({ message: "Wrong password ❌" });

    const token = jwt.sign(
      { id: adminDoc.id, email: adminData.email },
      process.env.JWT_SECRET,
      { expiresIn: "2h" }
    );
    res.json({ message: "Login successful ✅", token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==========================================
// 📝 EXAM MANAGEMENT ROUTES (ADMIN)
// ==========================================

// Create Exam
app.post("/api/exams", verifyAdmin, async (req, res) => {
  const { title, questions } = req.body;
  try {
    const docRef = await db.collection("exams").add({
      title,
      questions: questions || [],
      createdAt: new Date()
    });
    res.status(201).json({ message: "Exam created! ✅", id: docRef.id });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// Get All Exams
app.get("/api/exams", verifyAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection("exams").get();
    res.json(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// Delete Exam
app.delete("/api/exams/:id", verifyAdmin, async (req, res) => {
  try {
    await db.collection("exams").doc(req.params.id).delete();
    res.json({ message: "Exam deleted 🗑️" });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ADD QUESTION TO EXAM
app.post("/api/exams/:examId/questions", verifyAdmin, async (req, res) => {
  try {
    const docRef = db.collection("exams").doc(req.params.examId);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ message: "Exam not found" });

    let questions = doc.data().questions || [];
    questions.push(req.body); 

    await docRef.update({ questions });
    res.json({ message: "Question added successfully ✅" });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// DELETE SPECIFIC QUESTION
app.delete("/api/exams/:examId/questions/:questionIndex", verifyAdmin, async (req, res) => {
  try {
    const docRef = db.collection("exams").doc(req.params.examId);
    const doc = await docRef.get();
    let questions = doc.data().questions || [];
    
    questions.splice(Number(req.params.questionIndex), 1);

    await docRef.update({ questions });
    res.json({ message: "Question deleted 🗑️" });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// ==========================================
// 🎓 STUDENT ROUTES (PUBLIC)
// ==========================================

app.get("/api/public/exams", async (req, res) => {
  const snapshot = await db.collection("exams").get();
  res.json(snapshot.docs.map(doc => ({ 
    id: doc.id, 
    title: doc.data().title, 
    questionCount: doc.data().questions?.length || 0 
  })));
});

app.get("/api/public/exams/:id", async (req, res) => {
  const doc = await db.collection("exams").doc(req.params.id).get();
  res.json({ id: doc.id, ...doc.data() });
});

app.post("/api/public/submit", async (req, res) => {
  await db.collection("results").add({ ...req.body, submittedAt: new Date() });
  res.json({ message: "Result saved ✅" });
});

app.get("/api/results", verifyAdmin, async (req, res) => {
  const snapshot = await db.collection("results").get();
  res.json(snapshot.docs.map(doc => doc.data()));
});

// 4. Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});