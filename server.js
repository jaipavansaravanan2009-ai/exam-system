require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const admin = require("firebase-admin");

const bcrypt = require('bcryptjs');

async function createHashedPassword(plainPassword) {
    // The "Salt" makes the hash unique even if two users have the same password
    const saltRounds = 10; 
    
    // Generate the hash
    const hashedPassword = await bcrypt.hash(plainPassword, saltRounds);
    
    console.log("Original:", plainPassword);
    console.log("Hashed:", hashedPassword);
    
    return hashedPassword;
}

// Example: Creating a hash for a new Admin
// createHashedPassword("admin123");

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

// 2. Authorize Verification Middleware
function authorize(roles = []) {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ message: "No token provided" });

        const token = authHeader.split(" ")[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Check if user's role is allowed for this route
            if (roles.length && !roles.includes(decoded.role)) {
                return res.status(403).json({ message: "Unauthorized role 🚫" });
            }

            req.user = decoded;
            next();
        } catch (err) {
            return res.status(401).json({ message: "Invalid or expired token" });
        }
    };
}

// Example usage on routes:
app.post("/api/exams", authorize(["admin"]), createExam); // Only Admin
app.get("/api/exams", authorize(["admin", "setter", "student"]), getExams); // Everyone
app.post("/api/exams/:id/questions", authorize(["admin", "setter"]), addQuestion); // Admin & Setter

// ==========================================
// 🔑 ADMIN AUTH ROUTES
// ==========================================

// server.js - Unified Auth Route
app.post("/api/auth/login", async (req, res) => {
    const { username, password, role } = req.body; // username is the email

    try {
        // 1. Find user by email AND role
        const snapshot = await db.collection("users")
            .where("email", "==", username)
            .where("role", "==", role)
            .get();

        if (snapshot.empty) {
            return res.status(401).json({ message: "Invalid credentials or role ❌" });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();

        // 2. Verify hashed password
        const isMatch = await bcrypt.compare(password, userData.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Wrong password ❌" });
        }

        // 3. Create JWT token with role included
        const token = jwt.sign(
            { id: userDoc.id, email: userData.email, role: userData.role },
            process.env.JWT_SECRET,
            { expiresIn: "4h" }
        );

        // 4. Send success response
        res.json({
            message: "Login successful ✅",
            token: token,
            role: userData.role,
            username: userData.name || userData.email
        });

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
    const { studentName, examTitle, score } = req.body;
    try {
        // If using Firebase, save to a 'submissions' collection
        await db.collection("submissions").add({
            studentName,
            examTitle,
            score,
            submittedAt: new Date()
        });
        res.status(200).json({ message: "Score recorded successfully! ✅" });
    } catch (error) {
        res.status(500).json({ error: "Failed to save score" });
    }
});

app.post("/api/admin/create-user", async (req, res) => {
    const { email, password, role, name } = req.body;

    try {
        // 1. Hash the password before saving
        const hashedPassword = await bcrypt.hash(password, 10);

        // 2. Save the user to the "users" collection
        await db.collection("users").add({
            email,
            password: hashedPassword, // Store the HASH, never the plain text
            role,
            name,
            createdAt: new Date()
        });

        res.json({ message: "User created successfully! ✅" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const bcrypt = require('bcryptjs');

// Route to create a new user (Only accessible by Admin)
app.post("/api/admin/users", authorize(["admin"]), async (req, res) => {
    const { name, email, password, role } = req.body;

    try {
        // 1. Check if user already exists
        const existing = await db.collection("users").where("email", "==", email).get();
        if (!existing.empty) return res.status(400).json({ message: "Email already registered!" });

        // 2. HASH the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Save to Firestore
        await db.collection("users").add({
            name,
            email,
            password: hashedPassword,
            role,
            createdAt: new Date()
        });

        res.json({ message: `User ${name} created as ${role} ✅` });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
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