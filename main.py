import os
import json
import base64
from datetime import datetime, timedelta, timezone
import bcrypt
import jwt
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import firebase_admin
from firebase_admin import credentials, firestore
from dotenv import load_dotenv
from fastapi import UploadFile, File
import csv
import io

# Load Environment Variables
load_dotenv()

# 1. Firebase Setup
print("Checking Environment Variables...")
base64_key = os.environ.get("FIREBASE_BASE64")
if not base64_key:
    print("❌ ERROR: FIREBASE_BASE64 is missing from environment variables!")
    exit(1)

try:
    decoded_key = base64.b64decode(base64_key).decode('utf-8')
    service_account = json.loads(decoded_key)
    print("✅ Firebase Key decoded and parsed successfully.")
except Exception as e:
    print(f"❌ ERROR: Failed to parse decoded key! {e}")
    exit(1)

if not firebase_admin._apps:
    cred = credentials.Certificate(service_account)
    firebase_admin.initialize_app(cred)
    
db = firestore.client()
JWT_SECRET = os.environ.get("JWT_SECRET", "super-secret-key")

# 🚀 INITIALIZE FASTAPI APP
app = FastAPI()

# 🛡️ UNIFIED CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Middleware: Unified Authorization
def authorize(roles=None):
    if roles is None:
        roles = []
        
    def dependency(authorization: str = Header(None)):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="No token provided")
            
        token = authorization.split(" ")[1]
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            if roles and decoded.get("role") not in roles:
                raise HTTPException(status_code=403, detail="Unauthorized role 🚫")
            return decoded
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")
            
    return dependency

# 🔑 AUTHENTICATION ROUTES
@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    input_user = body.get("username", "").strip()
    input_pass = body.get("password", "").strip()
    input_role = body.get("role", "").strip()

    # Search Firestore (Python equivalent of JS logic)
    users_ref = db.collection("users")
    docs = users_ref.stream()
    
    user_doc = None
    user_data = None
    for doc in docs:
        data = doc.to_dict()
        matches_user = (data.get("email") == input_user or 
                        data.get("username") == input_user or 
                        data.get("Email") == input_user)
        matches_role = (data.get("role") == input_role)
        
        if matches_user and matches_role:
            user_doc = doc
            user_data = data
            break

    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid Credentials ❌")

    # Password Check
    stored_pass = user_data.get("password", "")
    is_match = (input_pass == stored_pass) # Fallback for plain text
    if not is_match:
        try:
            is_match = bcrypt.checkpw(input_pass.encode('utf-8'), stored_pass.encode('utf-8'))
        except:
            pass

    if not is_match:
        raise HTTPException(status_code=401, detail="Wrong password ❌")

    # Generate Token
    exp = datetime.now(timezone.utc) + timedelta(hours=12)
    payload = {
        "id": user_doc.id,
        "email": user_data.get("email") or input_user,
        "role": user_data.get("role"),
        "exp": exp
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return {
        "message": "Login successful ✅",
        "token": token,
        "role": user_data.get("role"),
        "username": user_data.get("name") or input_user
    }

# 👑 ADMIN & USER MANAGEMENT
@app.post("/api/admin/users")
async def create_user(request: Request, user=Depends(authorize(["admin"]))):
    body = await request.json()
    name = body.get("name")
    email = body.get("email")
    password = body.get("password", "")
    role = body.get("role")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    db.collection("users").add({
        "name": name,
        "email": email,
        "password": hashed_password,
        "role": role,
        "createdAt": datetime.now(timezone.utc)
    })
    return {"message": f"User {name} created ✅"}

# 📝 EXAM MANAGEMENT (ADMIN)
@app.post("/api/exams")
async def create_exam(request: Request, user=Depends(authorize(["admin"]))):
    body = await request.json()
    body["createdAt"] = datetime.now(timezone.utc)
    update_time, doc_ref = db.collection("exams").add(body)
    return {"message": "Exam created! ✅", "id": doc_ref.id}

# --- 🚀 BULK UPLOAD QUESTIONS VIA CSV ---
@app.post("/api/exams/{exam_id}/bulk-upload")
async def bulk_upload_questions(exam_id: str, file: UploadFile = File(...), user=Depends(authorize(["admin"]))):
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only .csv files are allowed.")

    try:
        # Read the CSV file
        contents = await file.read()
        decoded = contents.decode('utf-8')
        reader = csv.DictReader(io.StringIO(decoded))
        
        exam_ref = db.collection("exams").document(exam_id)
        doc = exam_ref.get()

        if not doc.exists:
            raise HTTPException(status_code=404, detail="Exam not found")

        data = doc.to_dict()
        questions = data.get("questions", [])
        
        # Process each row in the Excel/CSV file
        added_count = 0
        for row in reader:
            new_q = {
                "subject": row.get("Subject", "Physics").strip(),
                "question": row.get("QuestionText", "").strip(),
                "questionImage": row.get("QuestionImageURL", "").strip() or None,
                "options": [
                    row.get("OptionA", "").strip(),
                    row.get("OptionB", "").strip(),
                    row.get("OptionC", "").strip(),
                    row.get("OptionD", "").strip()
                ],
                "optionImages": [
                    row.get("OptionA_ImageURL", "").strip() or None,
                    row.get("OptionB_ImageURL", "").strip() or None,
                    row.get("OptionC_ImageURL", "").strip() or None,
                    row.get("OptionD_ImageURL", "").strip() or None
                ],
                # 🔥 AUTOMATICALLY SET OPTION A AS CORRECT 🔥
                "correctAnswer": row.get("OptionA", "").strip()
            }
            questions.append(new_q)
            added_count += 1
            
        exam_ref.update({"questions": questions})
        return {"message": f"Successfully added {added_count} questions! ✅"}
        
    except Exception as e:
        print(f"Bulk upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to process the CSV file. Check your columns.")

# --- 🔥 NEW: DELETE ENTIRE EXAM ROUTE 🔥 ---
@app.delete("/api/exams/{exam_id}")
async def delete_exam(exam_id: str, user=Depends(authorize(["admin"]))):
    try:
        db.collection("exams").document(exam_id).delete()
        return {"message": "Exam deleted successfully! 🗑️"}
    except Exception as e:
        print(f"Error deleting exam: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete exam from database")

@app.post("/api/exams/{exam_id}/questions")
async def add_question(exam_id: str, request: Request, user=Depends(authorize(["admin", "setter"]))):
    new_question = await request.json()
    exam_ref = db.collection("exams").document(exam_id)
    doc = exam_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")

    data = doc.to_dict()
    questions = data.get("questions", [])
    questions.append(new_question)
    
    exam_ref.update({"questions": questions})
    return {"message": "Question added successfully! ✅"}

@app.delete("/api/exams/{exam_id}/questions/{index}")
async def delete_question(exam_id: str, index: int, user=Depends(authorize(["admin"]))):
    exam_ref = db.collection("exams").document(exam_id)
    doc = exam_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")

    data = doc.to_dict()
    questions = data.get("questions", [])
    
    if 0 <= index < len(questions):
        questions.pop(index)
        exam_ref.update({"questions": questions})
        return {"message": "Question deleted!"}
        
    raise HTTPException(status_code=400, detail="Invalid index")

@app.get("/api/exams")
async def get_all_exams(user=Depends(authorize(["admin", "setter"]))):
    docs = db.collection("exams").stream()
    return [{**doc.to_dict(), "id": doc.id} for doc in docs]

# 🏆 PUBLIC ROUTES (FOR STUDENTS)
@app.get("/api/public/exams")
async def get_public_exams():
    docs = db.collection("exams").stream()
    exams_list = []
    
    for doc in docs:
        data = doc.to_dict()
        # Count the questions on the server side without sending the heavy image data
        q_count = len(data.get("questions", [])) 
        
        exams_list.append({
            "id": doc.id, 
            "title": data.get("title", "Untitled Exam"),
            "questionCount": q_count
        })
        
    return exams_list

@app.get("/api/public/exams/{exam_id}")
async def get_exam(exam_id: str):
    doc = db.collection("exams").document(exam_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")
        
    data = doc.to_dict()
    data["id"] = doc.id
    return data

@app.post("/api/public/submit")
async def submit_exam(request: Request):
    body = await request.json()
    body["submittedAt"] = datetime.now(timezone.utc)
    db.collection("results").add(body)
    return {"message": "Score recorded! ✅"}

# 📂 SERVE FRONTEND FILES (Must be at the bottom)
@app.get("/")
async def root():
    return FileResponse("frontend/login.html")

if os.path.exists("frontend"):
    # This serves your JS, CSS, and HTML files cleanly
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
else:
    print("⚠️ WARNING: 'frontend' folder not found!")