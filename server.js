require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const admin = require("firebase-admin");

// 1. Firebase Setup
console.log("Checking Environment Variables...");
const base64Key = process.env.FIREBASE_BASE64;
if (!base64Key) {
    console.error("❌ ERROR: FIREBASE_BASE64 is missing from Railway variables!");
    process.exit(1);
}

let serviceAccount;
try {
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

// 🚀 INITIALIZE EXPRESS APP
const app = express();

// 🛡️ UNIFIED CORS & MIDDLEWARE
app.use(cors({
    origin: "*", 
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json());

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

// 🔑 AUTHENTICATION ROUTES
app.post("/api/auth/login", async (req, res) => {
    const inputUser = req.body.username ? req.body.username.trim() : "";
    const inputPass = req.body.password ? req.body.password.trim() : "";
    const inputRole = req.body.role ? req.body.role.trim() : "";

    try {
        const snapshot = await db.collection("users").get();
        const userDoc = snapshot.docs.find(doc => {
            const data = doc.data();
            const matchesUser = (data.email === inputUser || data.username === inputUser || data.Email === inputUser);
            const matchesRole = (data.role === inputRole);
            return matchesUser && matchesRole;
        });

        if (!userDoc) return res.status(401).json({ message: "Invalid Credentials ❌" });

        const userData = userDoc.data();
        const isMatch = (inputPass === userData.password) || await bcrypt.compare(inputPass, userData.password);

        if (!isMatch) return res.status(401).json({ message: "Wrong password ❌" });

        const token = jwt.sign(
            { id: userDoc.id, email: userData.email || inputUser, role: userData.role },
            process.env.JWT_SECRET,
            { expiresIn: "12h" }
        );

        res.json({
            message: "Login successful ✅",
            token,
            role: userData.role,
            username: userData.name || inputUser
        });
    } catch (error) {
        res.status(500).json({ error: "Database connection failed" });
    }
});

// 👑 ADMIN & USER MANAGEMENT
app.post("/api/admin/users", authorize(["admin"]), async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection("users").add({
            name, email, password: hashedPassword, role, createdAt: new Date()
        });
        res.json({ message: `User ${name} created ✅` });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 📝 EXAM MANAGEMENT (ADMIN)
app.post("/api/exams", authorize(["admin"]), async (req, res) => {
    try {
        const docRef = await db.collection("exams").add({ ...req.body, createdAt: new Date() });
        res.status(201).json({ message: "Exam created! ✅", id: docRef.id });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get("/api/exams", authorize(["admin", "setter"]), async (req, res) => {
    try {
        const snapshot = await db.collection("exams").get();
        res.json(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// 🏆 PUBLIC ROUTES (FOR STUDENTS)
app.get("/api/public/exams", async (req, res) => {
    try {
        const snapshot = await db.collection("exams").get();
        res.json(snapshot.docs.map(doc => ({ id: doc.id, title: doc.data().title })));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/public/exams/:id', async (req, res) => {
    try {
        const doc = await db.collection('exams').doc(req.params.id).get();
        if (!doc.exists) return res.status(404).json({ message: "Exam not found" });
        res.json({ id: doc.id, ...doc.data() });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post("/api/public/submit", async (req, res) => {
    try {
        await db.collection("results").add({ ...req.body, submittedAt: new Date() });
        res.status(200).json({ message: "Score recorded! ✅" });
    } catch (error) { res.status(500).json({ error: "Failed to save score" }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT} ✅`));