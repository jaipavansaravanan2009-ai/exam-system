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
from fastapi import UploadFile, File, HTTPException, Depends
import zipfile
import mimetypes
import traceback
from PIL import Image

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

# --- 📦 BULLETPROOF BULK UPLOAD VIA ZIP (WITH AUTO-COMPRESS) ---
@app.post("/api/exams/{exam_id}/bulk-upload-zip")
async def bulk_upload_zip(exam_id: str, file: UploadFile = File(...), user=Depends(authorize(["admin"]))):
    if not file.filename.lower().endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only .zip files are allowed.")

    try:
        contents = await file.read()
        csv_data = None
        images_data = {}
        
        # 1. Unpack the ZIP file in memory 
        with zipfile.ZipFile(io.BytesIO(contents)) as z:
            for filename in z.namelist():
                base_name = filename.split('/')[-1]
                if "__MACOSX" in filename or base_name.startswith(".") or base_name.startswith("._") or filename.endswith("/"):
                    continue
                    
                if filename.lower().endswith(".csv"):
                    raw_csv = z.read(filename)
                    try:
                        csv_data = raw_csv.decode('utf-8-sig')
                    except UnicodeDecodeError:
                        try:
                            csv_data = raw_csv.decode('cp1252')
                        except UnicodeDecodeError:
                            csv_data = raw_csv.decode('latin-1')
                            
                elif filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp')):
                    img_bytes = z.read(filename)
                    
                    # 🔥 NEW: AUTOMATIC IMAGE COMPRESSION 🔥
                    try:
                        with Image.open(io.BytesIO(img_bytes)) as img:
                            # Convert to RGB (removes transparent backgrounds, making files smaller)
                            if img.mode in ("RGBA", "P"):
                                img = img.convert("RGB")
                            
                            # Resize if it's a massive high-res photo
                            max_width = 700
                            if img.width > max_width:
                                ratio = max_width / img.width
                                new_height = int(img.height * ratio)
                                img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
                                
                            # Compress heavily to 60% quality JPEG
                            buffer = io.BytesIO()
                            img.save(buffer, format="JPEG", quality=60)
                            b64_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
                            mime_type = "image/jpeg"
                    except Exception as e:
                        print(f"Image compression failed for {filename}, skipping compression.")
                        # Fallback if image is weird but readable
                        mime_type, _ = mimetypes.guess_type(filename)
                        if not mime_type: mime_type = "image/jpeg"
                        b64_str = base64.b64encode(img_bytes).decode('utf-8')

                    clean_name = base_name.lower().strip()
                    images_data[clean_name] = f"data:{mime_type};base64,{b64_str}"

        if not csv_data:
            raise HTTPException(status_code=400, detail="Could not find a valid .csv file inside the ZIP.")

        # 2. Parse the CSV
        reader = csv.DictReader(io.StringIO(csv_data))
        if not reader.fieldnames:
             raise HTTPException(status_code=400, detail="CSV file is completely empty or missing headers.")
             
        reader.fieldnames = [str(field).strip() for field in reader.fieldnames if field] 
        
        exam_ref = db.collection("exams").document(exam_id)
        doc = exam_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Exam not found")

        data = doc.to_dict()
        questions = data.get("questions", [])
        
        def get_val(row, possible_keys):
            for k in possible_keys:
                if k in row and row[k]: return str(row[k]).strip()
            return ""

        def get_img(row, possible_keys):
            img_name = get_val(row, possible_keys)
            if not img_name: return None
            if img_name.startswith("http"): return img_name
            return images_data.get(img_name.lower().strip(), None)

        # 3. Build Questions
        added_count = 0
        for row in reader:
            if not any(row.values()): continue

            # Get Images First
            img_q = get_img(row, ["QuestionImage", "QuestionImageURL", "question_image"])
            img_a = get_img(row, ["OptionA_Image", "OptionA_ImageURL", "ImageA"])
            img_b = get_img(row, ["OptionB_Image", "OptionB_ImageURL", "ImageB"])
            img_c = get_img(row, ["OptionC_Image", "OptionC_ImageURL", "ImageC"])
            img_d = get_img(row, ["OptionD_Image", "OptionD_ImageURL", "ImageD"])

            # Logic: Only use "Option X" text if there is NO image and NO text provided
            def smart_text(val, img, default):
                val = val.strip()
                if val: return val # Use user text if provided
                if img: return ""  # If there's an image and no text, keep text empty
                return default     # Fallback only if both are missing

            opt_a_text = smart_text(get_val(row, ["OptionA", "Option A"]), img_a, "Option A")
            opt_b_text = smart_text(get_val(row, ["OptionB", "Option B"]), img_b, "Option B")
            opt_c_text = smart_text(get_val(row, ["OptionC", "Option C"]), img_c, "Option C")
            opt_d_text = smart_text(get_val(row, ["OptionD", "Option D"]), img_d, "Option D")

            new_q = {
                "subject": get_val(row, ["Subject", "subject"]) or "Physics",
                "question": get_val(row, ["QuestionText", "Question", "question"]),
                "questionImage": img_q,
                "options": [opt_a_text, opt_b_text, opt_c_text, opt_d_text],
                "optionImages": [img_a, img_b, img_c, img_d],
                "correctAnswer": opt_a_text # This will match the text (even if empty)
            }
            questions.append(new_q)
            added_count += 1
            
        exam_ref.update({"questions": questions})
        return {"message": f"Successfully unpacked ZIP, compressed images, and added {added_count} questions! ✅"}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"System Crash: {str(e)}")
    

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

# [NEW]: GET LIVE DYNAMIC ANALYSIS & RANKING
@app.get("/api/public/results/{result_id}/analysis")
async def get_live_analysis(result_id: str, user = Depends(authorize(["student"]))):
    try:
        # 1. Get the specific result the student clicked on
        result_doc = db.collection("results").document(result_id).get()
        if not result_doc.exists:
            raise HTTPException(status_code=404, detail="Result not found.")
        
        my_result = result_doc.to_dict()
        
        # Security: Ensure the student isn't looking at someone else's result ID
        if my_result["studentName"] != user["name"]:
            raise HTTPException(status_code=403, detail="Unauthorized to view this result.")
            
        exam_id = my_result["examId"]
        my_total_score = my_result.get("totalScore", 0)
        my_subjects = my_result.get("subjectWiseBreakdown", {})
        
        # 2. Fetch ALL results for this exact Exam to compare against
        all_results_query = db.collection("results").where("examId", "==", exam_id).stream()
        
        total_scores = []
        subject_scores = {} # e.g., {"Physics": [34, 45, 12], "Chemistry": [...]}
        
        for doc in all_results_query:
            data = doc.to_dict()
            total_scores.append(data.get("totalScore", 0))
            
            breakdown = data.get("subjectWiseBreakdown", {})
            for sub, details in breakdown.items():
                if sub not in subject_scores:
                    subject_scores[sub] = []
                subject_scores[sub].append(details.get("score", 0))
                
        # 3. Sort all lists from Highest to Lowest (for Ranking)
        total_scores.sort(reverse=True)
        for sub in subject_scores:
            subject_scores[sub].sort(reverse=True)
            
        # 4. Calculate Live Metrics
        total_students = len(total_scores)
        
        # .index() naturally handles ties perfectly! (e.g., 100, 100, 90 -> Ranks 1, 1, 3)
        analysis = {
            "totalStudents": total_students,
            "overall": {
                "myScore": my_total_score,
                "rank": total_scores.index(my_total_score) + 1,
                "avg": round(sum(total_scores) / total_students, 1) if total_students else 0,
                "top": total_scores[0] if total_students else 0
            },
            "subjects": {}
        }
        
        # Calculate ranks and averages for each subject
        for sub, details in my_subjects.items():
            my_sub_score = details.get("score", 0)
            sub_list = subject_scores.get(sub, [my_sub_score])
            
            analysis["subjects"][sub] = {
                "myScore": my_sub_score,
                "rank": sub_list.index(my_sub_score) + 1,
                "avg": round(sum(sub_list) / len(sub_list), 1) if sub_list else 0,
                "top": sub_list[0] if sub_list else 0
            }
            
        return analysis
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/public/exams/{exam_id}")
async def get_exam(exam_id: str):
    doc = db.collection("exams").document(exam_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")
        
    data = doc.to_dict()
    data["id"] = doc.id
    return data

# 📂 SERVE FRONTEND FILES (Must be at the bottom)
@app.get("/")
async def root():
    return FileResponse("frontend/login.html")

if os.path.exists("frontend"):
    # This serves your JS, CSS, and HTML files cleanly
    app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
else:
    print("⚠️ WARNING: 'frontend' folder not found!")

    # --- 🏆 AUTHENTICATED PUBLIC ROUTES (FOR STUDENTS) ---

# [NEW]: GET FULL LIST OF Past Results for THE LOGGED IN STUDENT
@app.get("/api/public/results/my-results")
async def get_my_results(user = Depends(authorize(["student"]))):
    try:
        student_name = user["name"]
        
        # Filter by studentName and sort by newest first (descending timestamp)
        query = db.collection("results").where("studentName", "==", student_name).order_by("submittedAt", direction=db.firestore.Query.DESCENDING).stream()
        
        results_list = []
        for doc in query:
            data = doc.to_dict()
            results_list.append({
                "id": doc.id,
                # Convert Firestore Timestamp to readable format for frontend JSON deep-linking
                "submittedAt": data["submittedAt"].toJSON() if data.get("submittedAt") else None,
                **data
            })
            
        return results_list
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to fetch your results: {str(e)}")


# [NEW/UPDATED]: Authenticated SUBMIT Exam Route with Enrichment and Verification
@app.post("/api/public/submit")
async def submit_exam_detailed(result_payload: dict, user = Depends(authorize(["student"]))):
    student_name = user["name"]
    exam_title = result_payload.get("examTitle")
    exam_id = result_payload.get("examId")
    rich_breakdown = result_payload.get("subjectWiseBreakdown")

    if not all([exam_title, exam_id, rich_breakdown]):
        raise HTTPException(status_code=400, detail="Incomplete results data.")

    try:
        # Fetch the original exam to verify and enrich
        exam_doc = db.collection("exams").document(exam_id).get()
        if not exam_doc.exists:
            raise HTTPException(status_code=404, detail="Exam associated with this result not found.")
        exam_data = exam_doc.to_dict()
        exam_questions = exam_data.get("questions", [])

        # Calculate backend counts per subject and total questions
        total_questions_count = len(exam_questions)
        questions_count_per_subject = {}
        for q in exam_questions:
            subject = q["subject"]
            questions_count_per_subject[subject] = questions_count_per_subject.get(subject, 0) + 1

        # Enrich and Verify frontend breakdown
        verified_breakdown = {}
        calculated_total_score = 0
        total_correct_count = 0
        total_incorrect_count = 0
        total_not_attempted_count = 0

        for subject, frontend_section in rich_breakdown.items():
            if subject not in questions_count_per_subject:
                 # Should never happen if taking same exam. Security.
                 raise HTTPException(status_code=400, detail=f"Subject '{subject}' found in breakdown but not in exam questions.")

            section_total_available_marks = 4 * questions_count_per_subject[subject]
            
            # Rely on frontend counts for shuffled options, but backend recalculates score. Calculated score is trusted.
            expected_score = (frontend_section['correct'] * 4) - (frontend_section['incorrect'] * 1)
            
            # if expected_score != frontend_section['score']:
            #     print(f"Warning: Frontend score ({frontend_section['score']}) differs from backend ({expected_score}) for {subject}. Using backend.")

            total_correct_count += frontend_section['correct']
            total_incorrect_count += frontend_section['incorrect']
            total_not_attempted_count += frontend_section['notAttempted']
            calculated_total_score += expected_score

            # Create enriched section object
            verified_section = {
                "score": expected_score,
                "correct": frontend_section['correct'],
                "incorrect": frontend_section['incorrect'],
                "notAttempted": frontend_section['notAttempted'],
                "markedForReviewCount": frontend_section.get('markedForReviewCount', 0), 
                "subjectTotalMarks": section_total_available_marks,
                "subjectQuestionsCount": questions_count_per_subject[subject]
            }
            verified_breakdown[subject] = verified_section

        # Trust frontend counts, verify backend score.

        new_result_doc = {
            "studentName": student_name,
            "examTitle": exam_title,
            "examId": exam_id,
            "submittedAt": db.firestore.SERVER_TIMESTAMP,
            "examQuestionsCount": total_questions_count,
            "totalScore": calculated_total_score,
            "subjectWiseBreakdown": verified_breakdown
        }

        db.collection("results").add(new_result_doc)
        return {"message": "Exam submitted successfully!"}

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to submit result: {str(e)}")