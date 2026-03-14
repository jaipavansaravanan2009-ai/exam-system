require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");

// 1. Firebase Setup (BULLETPROOF BASE64 METHOD)
console.log("Checking Environment Variables...");

const base64Key = process.env.FIREBASE_BASE64;
if (!base64Key) {
    console.error("❌ ERROR: FIREBASE_BASE64 is missing from Railway variables!");
    process.exit(1);
}

let serviceAccount;
try {
    // Decode the unbreakable string back into JSON
    const decodedKey = Buffer.from(base64Key, 'base64').toString('utf-8');
    serviceAccount = JSON.parse(decodedKey);
    console.log("✅ Firebase Key decoded and parsed successfully.");
} catch (err) {
    console.error("❌ ERROR: Failed to parse decoded key!", err.message);
    process.exit(1);
}

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}
const db = admin.firestore();

// ==========================================
// 🚀 INITIALIZE EXPRESS APP
// ==========================================
const app = express();

// ==========================================
// 🛡️ CRITICAL: UNIFIED CORS & MIDDLEWARE
// ==========================================
// This stays at the top of the app usage to prevent 502/Preflight errors
app.use(cors({
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

console.log("Server logic initialized... 🚀");

// 2. Middleware: Unified Authorization
function authorize(roles = []) {
    return (req, res, next) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ message: "No token provided" });

        const token = authHeader.split(" ")[1];
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
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

// ==========================================
// 🔑 AUTHENTICATION ROUTES
// ==========================================

app.post("/api/auth/login", async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const snapshot = await db.collection("users")
            .where("email", "==", username)
            .where("role", "==", role)
            .get();

        if (snapshot.empty) {
            return res.status(401).json({ message: "Invalid credentials or role ❌" });
        }

        const userDoc = snapshot.docs[0];
        const userData = userDoc.data();

        const isMatch = await bcrypt.compare(password, userData.password);
        if (!isMatch) {
            return res.status(401).json({ message: "Wrong password ❌" });
        }

        const token = jwt.sign(
            { id: userDoc.id, email: userData.email, role: userData.role },
            process.env.JWT_SECRET,
            { expiresIn: "12h" }
        );

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
// 👑 ADMIN & USER MANAGEMENT
// ==========================================

app.post("/api/admin/users", authorize(["admin"]), async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const existing = await db.collection("users").where("email", "==", email).get();
        if (!existing.empty) return res.status(400).json({ message: "Email already registered!" });

        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection("users").add({
            name, email, password: hashedPassword, role, createdAt: new Date()
        });
        res.json({ message: `User ${name} created as ${role} ✅` });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ==========================================
// 📝 EXAM MANAGEMENT
// ==========================================

app.post("/api/exams", authorize(["admin"]), async (req, res) => {
    const { title, questions } = req.body;
    try {
        const docRef = await db.collection("exams").add({
            title, questions: questions || [], createdAt: new Date()
        });
        res.status(201).json({ message: "Exam created! ✅", id: docRef.id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get("/api/exams", authorize(["admin", "setter"]), async (req, res) => {
    try {
        const snapshot = await db.collection("exams").get();
        res.json(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete("/api/exams/:id", authorize(["admin"]), async (req, res) => {
    try {
        await db.collection("exams").doc(req.params.id).delete();
        res.json({ message: "Exam deleted 🗑️" });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ==========================================
// 🏆 RESULTS & PUBLIC ROUTES
// ==========================================

app.post("/api/public/submit", async (req, res) => {
    const { studentName, examTitle, score } = req.body;
    try {
        await db.collection("results").add({
            studentName, examTitle, score, submittedAt: new Date()
        });
        res.status(200).json({ message: "Score recorded successfully! ✅" });
    } catch (error) { res.status(500).json({ error: "Failed to save score" }); }
});

app.get("/api/results", authorize(["admin"]), async (req, res) => {
    try {
        const snapshot = await db.collection("results").get();
        res.json(snapshot.docs.map(doc => doc.data()));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get("/api/public/exams", async (req, res) => {
    try {
        const snapshot = await db.collection("exams").get();
        res.json(snapshot.docs.map(doc => ({ 
            id: doc.id, 
            title: doc.data().title, 
            questionCount: doc.data().questions?.length || 0 
        })));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 4. Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT} ✅`);
});