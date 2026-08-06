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
from typing import List
import csv
import io
import zipfile
import mimetypes
import traceback
from PIL import Image
from fastapi.responses import RedirectResponse

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

# 🏠 ROOT ROUTE - Redirect to login page
@app.get("/")
def home():
    return RedirectResponse(url="/login.html")

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


# ==========================================
# 🔑 AUTHENTICATION ROUTES
# ==========================================
@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    input_user = body.get("username", "").strip()
    input_pass = body.get("password", "").strip()
    input_role = body.get("role", "").strip()

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

    stored_pass = user_data.get("password", "")
    is_match = (input_pass == stored_pass)
    if not is_match:
        try:
            is_match = bcrypt.checkpw(input_pass.encode('utf-8'), stored_pass.encode('utf-8'))
        except:
            pass

    if not is_match:
        raise HTTPException(status_code=401, detail="Wrong password ❌")

    exp = datetime.now(timezone.utc) + timedelta(hours=12)
    payload = {
        "id": user_doc.id,
        "email": user_data.get("email") or input_user,
        "role": user_data.get("role"),
        "name": user_data.get("name") or input_user, 
        "exp": exp
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return {
        "message": "Login successful ✅",
        "token": token,
        "role": user_data.get("role"),
        "username": user_data.get("name") or input_user
    }


# ==========================================
# 👑 ADMIN & USER MANAGEMENT
# ==========================================
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


# ==========================================
# 📝 EXAM MANAGEMENT (ADMIN)
# ==========================================
@app.post("/api/exams")
async def create_exam(request: Request, user=Depends(authorize(["admin"]))):
    body = await request.json()
    body["createdAt"] = datetime.now(timezone.utc)
    body["enableHints"] = body.get("enableHints", False)
    body["examType"] = body.get("examType", body.get("exam_type", "Practice"))
    update_time, doc_ref = db.collection("exams").add(body)
    return {"message": "Exam created! ✅", "id": doc_ref.id}

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

@app.post("/api/exams/{exam_id}/import-questions")
async def import_questions(exam_id: str, request: Request, user=Depends(authorize(["admin", "setter"]))):
    questions_to_add = await request.json()
    exam_ref = db.collection("exams").document(exam_id)
    doc = exam_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")

    data = doc.to_dict()
    questions = data.get("questions", [])
    questions.extend(questions_to_add) 
    
    exam_ref.update({"questions": questions})
    return {"message": f"{len(questions_to_add)} questions imported successfully! ✅"}

@app.put("/api/exams/{exam_id}/questions/{index}")
async def update_question(exam_id: str, index: int, request: Request, user=Depends(authorize(["admin", "setter"]))):
    updated_question = await request.json()
    exam_ref = db.collection("exams").document(exam_id)
    doc = exam_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")

    data = doc.to_dict()
    questions = data.get("questions", [])
    
    if 0 <= index < len(questions):
        questions[index] = updated_question 
        exam_ref.update({"questions": questions})
        return {"message": "Question updated successfully! ✅"}
        
    raise HTTPException(status_code=400, detail="Invalid index")

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
    exams = []
    for doc in docs:
        data = doc.to_dict()
        data["id"] = doc.id
        # Normalize exam type field
        if "exam_type" in data and "examType" not in data:
            data["examType"] = data["exam_type"]
        exams.append(data)
    return exams

@app.post("/api/exams/{exam_id}/bulk-upload-zip")
async def bulk_upload_zip(exam_id: str, files: List[UploadFile] = File(...), user=Depends(authorize(["admin", "setter"]))):
    exam_ref = db.collection("exams").document(exam_id)
    doc = exam_ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")
    
    data = doc.to_dict()
    questions = data.get("questions", [])
    
    total_added = 0
    file_results = []

    try:
        for file in files:
            if not file.filename.lower().endswith('.zip'):
                file_results.append({"file": file.filename, "status": "skipped", "reason": "Not a ZIP file"})
                continue

            try:
                contents = await file.read()
                csv_data = None
                images_data = {}
                
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
                            try:
                                with Image.open(io.BytesIO(img_bytes)) as img:
                                    if img.mode in ("RGBA", "P"):
                                        img = img.convert("RGB")
                                
                                    max_width = 700
                                    if img.width > max_width:
                                        ratio = max_width / img.width
                                        new_height = int(img.height * ratio)
                                        img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
                                
                                    buffer = io.BytesIO()
                                    img.save(buffer, format="JPEG", quality=60)
                                    b64_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
                                    mime_type = "image/jpeg"
                            except Exception as e:
                                print(f"Image compression failed for {filename}, skipping compression.")
                                mime_type, _ = mimetypes.guess_type(filename)
                                if not mime_type: mime_type = "image/jpeg"
                                b64_str = base64.b64encode(img_bytes).decode('utf-8')
                            
                            clean_name = base_name.lower().strip()
                            images_data[clean_name] = f"data:{mime_type};base64,{b64_str}"

                if not csv_data:
                    file_results.append({"file": file.filename, "status": "failed", "reason": "No CSV found in ZIP"})
                    continue

                reader = csv.DictReader(io.StringIO(csv_data))
                if not reader.fieldnames:
                     file_results.append({"file": file.filename, "status": "failed", "reason": "CSV missing headers"})
                     continue
                     
                reader.fieldnames = [str(field).strip() for field in reader.fieldnames if field]
                
                def get_val(row, possible_keys):
                    for k in possible_keys:
                        if k in row and row[k]: return str(row[k]).strip()
                    return ""

                def get_img(row, possible_keys):
                    img_name = get_val(row, possible_keys)
                    if not img_name: return None
                    if img_name.startswith("http"): return img_name
                    return images_data.get(img_name.lower().strip(), None)

                file_added = 0
                for row in reader:
                    if not any(row.values()): continue

                    img_q = get_img(row, ["QuestionImage", "QuestionImageURL", "question_image"])
                    img_a = get_img(row, ["OptionA_Image", "OptionA_ImageURL", "ImageA"])
                    img_b = get_img(row, ["OptionB_Image", "OptionB_ImageURL", "ImageB"])
                    img_c = get_img(row, ["OptionC_Image", "OptionC_ImageURL", "ImageC"])
                    img_d = get_img(row, ["OptionD_Image", "OptionD_ImageURL", "ImageD"])

                    def smart_text(val, img, default):
                        val = val.strip()
                        if val: return val
                        if img: return ""  
                        return default    

                    opt_a_text = smart_text(get_val(row, ["OptionA", "Option A"]), img_a, "Option A")
                    opt_b_text = smart_text(get_val(row, ["OptionB", "Option B"]), img_b, "Option B")
                    opt_c_text = smart_text(get_val(row, ["OptionC", "Option C"]), img_c, "Option C")
                    opt_d_text = smart_text(get_val(row, ["OptionD", "Option D"]), img_d, "Option D")
                    
                    section_type = get_val(row, ["Section", "section"]) or "Single correct answer"
                    numerical_ans = get_val(row, ["NumericalAnswer", "Numerical Answer", "Numerical_Answer"])

                    correct_ans = opt_a_text
                    if "integer" in section_type.lower() or "numerical" in section_type.lower():
                        correct_ans = numerical_ans
                        opt_a_text, opt_b_text, opt_c_text, opt_d_text = "", "", "", ""

                    new_q = {
                        "subject": get_val(row, ["Subject", "subject"]) or "Physics",
                        "section": section_type,
                        "question": get_val(row, ["QuestionText", "Question", "question"]),
                        "questionImage": img_q,
                        "options": [opt_a_text, opt_b_text, opt_c_text, opt_d_text] if not numerical_ans else [],
                        "optionImages": [img_a, img_b, img_c, img_d] if not numerical_ans else [],
                        "correctAnswer": correct_ans
                    }
                    questions.append(new_q)
                    file_added += 1
                
                file_results.append({"file": file.filename, "status": "success", "added": file_added})
                total_added += file_added
                
            except Exception as file_error:
                file_results.append({"file": file.filename, "status": "error", "reason": str(file_error)})
        
        exam_ref.update({"questions": questions})
        
        success_files = [r for r in file_results if r["status"] == "success"]
        failed_files = [r for r in file_results if r["status"] != "success"]
        
        response = {
            "message": f"Processed {len(files)} ZIP file(s). Total questions added: {total_added} ✅",
            "total_added": total_added,
            "files_processed": len(files),
            "successful_files": len(success_files),
            "failed_files": len(failed_files),
            "details": file_results
        }
        return response

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"System Crash: {str(e)}")

# ==========================================
# 🗄️ QUESTION BANK MANAGEMENT
# ==========================================
@app.get("/api/question_bank")
async def get_question_bank(
    subject: str = None, # NEW: Added subject filter parameter
    section: str = None, # NEW: Added section filter parameter
    topic: str = None,   # NEW: Added topic filter parameter
    user=Depends(authorize(["admin", "setter"]))
):
    try:
        # NEW: Apply Firestore filters where directly possible
        query = db.collection("question_bank")
        if subject:
            query = query.where("subject", "==", subject)
        if section:
            query = query.where("section", "==", section)
            
        docs = query.stream()
        results = []
        
        for doc in docs:
            data = doc.to_dict()
            
            # NEW: Post-filter by topic (robust, case-insensitive substring search across topics array)
            if topic:
                topic_lower = topic.lower()
                topics_list = data.get("topics", [])
                if not any(topic_lower in t.lower() for t in topics_list):
                    continue
                    
            results.append({**data, "id": doc.id})
            
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch question bank: {str(e)}")

@app.post("/api/question_bank")
async def add_qb_question(request: Request, user=Depends(authorize(["admin", "setter"]))):
    try:
        body = await request.json()
        body["createdAt"] = datetime.now(timezone.utc)
        body["createdBy"] = user.get("id")
        body["creatorRole"] = user.get("role")
        update_time, doc_ref = db.collection("question_bank").add(body)
        return {"message": "Question added to bank! ✅", "id": doc_ref.id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add question: {str(e)}")

@app.put("/api/question_bank/{q_id}")
async def update_qb_question(q_id: str, request: Request, user=Depends(authorize(["admin"]))):
    try:
        body = await request.json()
        body["updatedAt"] = datetime.now(timezone.utc) 
        db.collection("question_bank").document(q_id).update(body)
        return {"message": "Question updated in bank! ✅"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update question: {str(e)}")

@app.delete("/api/question_bank/{q_id}")
async def delete_qb_question(q_id: str, user=Depends(authorize(["admin"]))):
    try:
        db.collection("question_bank").document(q_id).delete()
        return {"message": "Question deleted from bank! 🗑️"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to delete question")

@app.post("/api/question_bank/bulk-upload-zip")
async def qb_bulk_upload_zip(files: List[UploadFile] = File(...), user=Depends(authorize(["admin", "setter"]))):
    total_added = 0
    file_results = []
    qb_ref = db.collection("question_bank")

    try:
        for file in files:
            if not file.filename.lower().endswith('.zip'):
                file_results.append({"file": file.filename, "status": "skipped", "reason": "Not a ZIP file"})
                continue

            try:
                contents = await file.read()
                csv_data = None
                images_data = {}
                
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
                            try:
                                with Image.open(io.BytesIO(img_bytes)) as img:
                                    if img.mode in ("RGBA", "P"):
                                        img = img.convert("RGB")
                                    max_width = 700
                                    if img.width > max_width:
                                        ratio = max_width / img.width
                                        new_height = int(img.height * ratio)
                                        img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
                                
                                    buffer = io.BytesIO()
                                    img.save(buffer, format="JPEG", quality=60)
                                    b64_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
                                    mime_type = "image/jpeg"
                            except Exception as e:
                                mime_type, _ = mimetypes.guess_type(filename)
                                if not mime_type: mime_type = "image/jpeg"
                                b64_str = base64.b64encode(img_bytes).decode('utf-8')
                            
                            clean_name = base_name.lower().strip()
                            images_data[clean_name] = f"data:{mime_type};base64,{b64_str}"

                if not csv_data:
                    file_results.append({"file": file.filename, "status": "failed", "reason": "No CSV found in ZIP"})
                    continue

                reader = csv.DictReader(io.StringIO(csv_data))
                reader.fieldnames = [str(field).strip() for field in reader.fieldnames if field]
                
                def get_val(row, possible_keys):
                    for k in possible_keys:
                        if k in row and row[k]: return str(row[k]).strip()
                    return ""

                def get_img(row, possible_keys):
                    img_name = get_val(row, possible_keys)
                    if not img_name: return None
                    if img_name.startswith("http"): return img_name
                    return images_data.get(img_name.lower().strip(), None)

                added_count = 0
                batch = db.batch()

                for row in reader:
                    if not any(row.values()): continue

                    img_q = get_img(row, ["QuestionImage", "QuestionImageURL", "question_image"])
                    img_a = get_img(row, ["OptionA_Image", "OptionA_ImageURL", "ImageA"])
                    img_b = get_img(row, ["OptionB_Image", "OptionB_ImageURL", "ImageB"])
                    img_c = get_img(row, ["OptionC_Image", "OptionC_ImageURL", "ImageC"])
                    img_d = get_img(row, ["OptionD_Image", "OptionD_ImageURL", "ImageD"])
                    img_sol = get_img(row, ["SolutionImage", "Solution_Image"])

                    opt_a_text = get_val(row, ["OptionA", "Option A"])
                    opt_b_text = get_val(row, ["OptionB", "Option B"])
                    opt_c_text = get_val(row, ["OptionC", "Option C"])
                    opt_d_text = get_val(row, ["OptionD", "Option D"])
                    
                    section_val = get_val(row, ["Section", "section"]) or "Single correct answer"
                    numerical_ans = get_val(row, ["NumericalAnswer", "Numerical Answer", "Numerical_Answer"])

                    correct_ans_list = [opt_a_text] if opt_a_text else []
                    if "integer" in section_val.lower() or "numerical" in section_val.lower():
                        correct_ans_list = [numerical_ans] if numerical_ans else []

                    new_q = {
                        "exam_type": get_val(row, ["ExamType", "exam_type"]) or "Practice",
                        "subject": get_val(row, ["Subject", "subject"]) or "Physics",
                        "section": section_val,
                        "question": get_val(row, ["QuestionText", "Question", "question"]),
                        "questionImage": img_q,
                        "options": [opt_a_text, opt_b_text, opt_c_text, opt_d_text] if not numerical_ans else [],
                        "optionImages": [img_a, img_b, img_c, img_d] if not numerical_ans else [],
                        "correctAnswers": correct_ans_list,
                        "hint": get_val(row, ["Hint", "hint"]),
                        "solution": get_val(row, ["Solution", "solution"]),
                        "solutionImage": img_sol,
                        "topics": [t.strip() for t in get_val(row, ["Topics", "topics"]).split(",") if t.strip()],
                        "createdAt": datetime.now(timezone.utc),
                        "createdBy": user.get("id")
                    }
                    
                    new_doc_ref = qb_ref.document()
                    batch.set(new_doc_ref, new_q)
                    added_count += 1
                    
                    if added_count % 450 == 0:
                        batch.commit()
                        batch = db.batch()
                
                batch.commit()
                file_results.append({"file": file.filename, "status": "success", "added": added_count})
                total_added += added_count
                    
            except Exception as file_error:
                file_results.append({"file": file.filename, "status": "error", "reason": str(file_error)})
        
        success_files = [r for r in file_results if r["status"] == "success"]
        failed_files = [r for r in file_results if r["status"] != "success"]
        
        response = {
            "message": f"Processed {len(files)} ZIP file(s). Total questions added: {total_added} ✅",
            "total_added": total_added,
            "files_processed": len(files),
            "successful_files": len(success_files),
            "failed_files": len(failed_files),
            "details": file_results
        }
        return response

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"System Crash: {str(e)}")

# ==========================================
# 📁 QUESTION LIST MANAGEMENT
# ==========================================
@app.get("/api/question_lists")
async def get_question_lists(user=Depends(authorize(["admin", "setter"]))):
    try:
        docs = db.collection("question_lists").order_by("createdAt", direction=firestore.Query.DESCENDING).stream()
        results = []
        for doc in docs:
            data = doc.to_dict()
            results.append({**data, "id": doc.id})
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch question lists: {str(e)}")

@app.post("/api/question_lists")
async def create_question_list(request: Request, user=Depends(authorize(["admin", "setter"]))):
    try:
        body = await request.json()
        name = body.get("name", "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="List name is required")
        
        new_list = {
            "name": name,
            "description": body.get("description", "").strip(),
            "createdAt": datetime.now(timezone.utc),
            "createdBy": user.get("id"),
            "createdByName": user.get("name") or "Unknown",
            "questionIds": []
        }
        update_time, doc_ref = db.collection("question_lists").add(new_list)
        return {"message": "Question list created! ✅", "id": doc_ref.id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create question list: {str(e)}")

@app.put("/api/question_lists/{list_id}")
async def update_question_list(list_id: str, request: Request, user=Depends(authorize(["admin", "setter"]))):
    try:
        body = await request.json()
        updates = {}
        if "name" in body and body["name"].strip():
            updates["name"] = body["name"].strip()
        if "description" in body:
            updates["description"] = body["description"].strip()
        updates["updatedAt"] = datetime.now(timezone.utc)
        
        if updates:
            db.collection("question_lists").document(list_id).update(updates)
        return {"message": "Question list updated! ✅"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update question list: {str(e)}")

@app.delete("/api/question_lists/{list_id}")
async def delete_question_list(list_id: str, user=Depends(authorize(["admin", "setter"]))):
    try:
        db.collection("question_lists").document(list_id).delete()
        return {"message": "Question list deleted! 🗑️"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to delete question list")

# 🗑️ Delete entire question list with all questions (from bank too)
@app.delete("/api/question_lists/{list_id}/full-delete")
async def full_delete_question_list(list_id: str, user=Depends(authorize(["admin"]))):
    try:
        list_ref = db.collection("question_lists").document(list_id)
        list_doc = list_ref.get()
        
        if not list_doc.exists:
            raise HTTPException(status_code=404, detail="Question list not found")
        
        list_data = list_doc.to_dict()
        question_ids = list_data.get("questionIds", [])
        
        # Delete all questions from question_bank
        batch = db.batch()
        for q_id in question_ids:
            q_ref = db.collection("question_bank").document(q_id)
            batch.delete(q_ref)
        
        # Delete the list itself
        batch.delete(list_ref)
        
        # Commit all deletions
        batch.commit()
        
        return {"message": f"Deleted list and {len(question_ids)} question(s) completely! 🗑️✅"}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to fully delete list: {str(e)}")

@app.get("/api/question_lists/{list_id}")
async def get_question_list_detail(list_id: str, user=Depends(authorize(["admin", "setter"]))):
    try:
        doc = db.collection("question_lists").document(list_id).get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Question list not found")
        
        data = doc.to_dict()
        question_ids = data.get("questionIds", [])
        
        # Fetch full question details from question_bank
        questions = []
        for q_id in question_ids:
            q_doc = db.collection("question_bank").document(q_id).get()
            if q_doc.exists:
                q_data = q_doc.to_dict()
                q_data["id"] = q_doc.id
                questions.append(q_data)
        
        return {**data, "id": doc.id, "questions": questions}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch question list: {str(e)}")

# 🔥 NEW: Clear all questions from a question list (but keep the list itself)
@app.delete("/api/question_lists/{list_id}/questions")
async def clear_question_list(list_id: str, user=Depends(authorize(["admin", "setter"]))):
    try:
        list_ref = db.collection("question_lists").document(list_id)
        doc = list_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Question list not found")
        
        data = doc.to_dict()
        question_count = len(data.get("questionIds", []))
        
        list_ref.update({
            "questionIds": [],
            "updatedAt": datetime.now(timezone.utc)
        })
        
        return {"message": f"Cleared {question_count} question(s) from list! 🗑️✅"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear question list: {str(e)}")

@app.post("/api/question_lists/{list_id}/bulk-upload-zip")
async def ql_bulk_upload_zip(list_id: str, files: List[UploadFile] = File(...), user=Depends(authorize(["admin", "setter"]))):
    # Verify the list exists
    list_ref = db.collection("question_lists").document(list_id)
    list_doc = list_ref.get()
    if not list_doc.exists:
        raise HTTPException(status_code=404, detail="Question list not found")

    total_added = 0
    file_results = []
    qb_ref = db.collection("question_bank")

    try:
        for file in files:
            if not file.filename.lower().endswith('.zip'):
                file_results.append({"file": file.filename, "status": "skipped", "reason": "Not a ZIP file"})
                continue

            try:
                contents = await file.read()
                csv_data = None
                images_data = {}
                
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
                            try:
                                with Image.open(io.BytesIO(img_bytes)) as img:
                                    if img.mode in ("RGBA", "P"):
                                        img = img.convert("RGB")
                                    max_width = 700
                                    if img.width > max_width:
                                        ratio = max_width / img.width
                                        new_height = int(img.height * ratio)
                                        img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
                                
                                    buffer = io.BytesIO()
                                    img.save(buffer, format="JPEG", quality=60)
                                    b64_str = base64.b64encode(buffer.getvalue()).decode('utf-8')
                                    mime_type = "image/jpeg"
                            except Exception as e:
                                mime_type, _ = mimetypes.guess_type(filename)
                                if not mime_type: mime_type = "image/jpeg"
                                b64_str = base64.b64encode(img_bytes).decode('utf-8')
                            
                            clean_name = base_name.lower().strip()
                            images_data[clean_name] = f"data:{mime_type};base64,{b64_str}"

                if not csv_data:
                    file_results.append({"file": file.filename, "status": "failed", "reason": "No CSV found in ZIP"})
                    continue

                reader = csv.DictReader(io.StringIO(csv_data))
                reader.fieldnames = [str(field).strip() for field in reader.fieldnames if field]
                
                def get_val(row, possible_keys):
                    for k in possible_keys:
                        if k in row and row[k]: return str(row[k]).strip()
                    return ""

                def get_img(row, possible_keys):
                    img_name = get_val(row, possible_keys)
                    if not img_name: return None
                    if img_name.startswith("http"): return img_name
                    return images_data.get(img_name.lower().strip(), None)

                file_added = 0
                new_question_ids = []
                batch = db.batch()

                for row in reader:
                    if not any(row.values()): continue

                    img_q = get_img(row, ["QuestionImage", "QuestionImageURL", "question_image"])
                    img_a = get_img(row, ["OptionA_Image", "OptionA_ImageURL", "ImageA"])
                    img_b = get_img(row, ["OptionB_Image", "OptionB_ImageURL", "ImageB"])
                    img_c = get_img(row, ["OptionC_Image", "OptionC_ImageURL", "ImageC"])
                    img_d = get_img(row, ["OptionD_Image", "OptionD_ImageURL", "ImageD"])
                    img_sol = get_img(row, ["SolutionImage", "Solution_Image"])

                    opt_a_text = get_val(row, ["OptionA", "Option A"])
                    opt_b_text = get_val(row, ["OptionB", "Option B"])
                    opt_c_text = get_val(row, ["OptionC", "Option C"])
                    opt_d_text = get_val(row, ["OptionD", "Option D"])
                    
                    section_val = get_val(row, ["Section", "section"]) or "Single correct answer"
                    numerical_ans = get_val(row, ["NumericalAnswer", "Numerical Answer", "Numerical_Answer"])

                    correct_ans_list = [opt_a_text] if opt_a_text else []
                    if "integer" in section_val.lower() or "numerical" in section_val.lower():
                        correct_ans_list = [numerical_ans] if numerical_ans else []

                    new_q = {
                        "exam_type": get_val(row, ["ExamType", "exam_type"]) or "Practice",
                        "subject": get_val(row, ["Subject", "subject"]) or "Physics",
                        "section": section_val,
                        "question": get_val(row, ["QuestionText", "Question", "question"]),
                        "questionImage": img_q,
                        "options": [opt_a_text, opt_b_text, opt_c_text, opt_d_text] if not numerical_ans else [],
                        "optionImages": [img_a, img_b, img_c, img_d] if not numerical_ans else [],
                        "correctAnswers": correct_ans_list,
                        "hint": get_val(row, ["Hint", "hint"]),
                        "solution": get_val(row, ["Solution", "solution"]),
                        "solutionImage": img_sol,
                        "topics": [t.strip() for t in get_val(row, ["Topics", "topics"]).split(",") if t.strip()],
                        "createdAt": datetime.now(timezone.utc),
                        "createdBy": user.get("id")
                    }
                    
                    new_doc_ref = qb_ref.document()
                    batch.set(new_doc_ref, new_q)
                    new_question_ids.append(new_doc_ref.id)
                    file_added += 1
                    
                    if file_added % 450 == 0:
                        batch.commit()
                        batch = db.batch()
                
                batch.commit()
                
                # Add all new question IDs to the list
                if new_question_ids:
                    list_ref.update({
                        "questionIds": firestore.ArrayUnion(new_question_ids)
                    })
                
                file_results.append({"file": file.filename, "status": "success", "added": file_added})
                total_added += file_added
                    
            except Exception as file_error:
                file_results.append({"file": file.filename, "status": "error", "reason": str(file_error)})
        
        success_files = [r for r in file_results if r["status"] == "success"]
        failed_files = [r for r in file_results if r["status"] != "success"]
        
        response = {
            "message": f"Processed {len(files)} ZIP file(s). Total questions added to Bank & List: {total_added} ✅",
            "total_added": total_added,
            "files_processed": len(files),
            "successful_files": len(success_files),
            "failed_files": len(failed_files),
            "details": file_results
        }
        return response

    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"System Crash: {str(e)}")

@app.post("/api/question_lists/{list_id}/questions")
async def add_questions_to_list(list_id: str, request: Request, user=Depends(authorize(["admin", "setter"]))):
    try:
        body = await request.json()
        question_ids = body.get("questionIds", [])
        if not question_ids:
            raise HTTPException(status_code=400, detail="No question IDs provided")
        
        list_ref = db.collection("question_lists").document(list_id)
        doc = list_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Question list not found")
        
        data = doc.to_dict()
        existing_ids = set(data.get("questionIds", []))
        new_ids = [qid for qid in question_ids if qid not in existing_ids]
        
        if new_ids:
            list_ref.update({
                "questionIds": firestore.ArrayUnion(new_ids)
            })
        
        return {"message": f"{len(new_ids)} question(s) added to list! ✅"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add questions to list: {str(e)}")

@app.delete("/api/question_lists/{list_id}/questions/{question_id}")
async def remove_question_from_list(list_id: str, question_id: str, user=Depends(authorize(["admin", "setter"]))):
    try:
        list_ref = db.collection("question_lists").document(list_id)
        doc = list_ref.get()
        if not doc.exists:
            raise HTTPException(status_code=404, detail="Question list not found")
        
        list_ref.update({
            "questionIds": firestore.ArrayRemove([question_id])
        })
        return {"message": "Question removed from list! ✅"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove question: {str(e)}")

# 🔄 Replace a question in a list (maintains order)
@app.put("/api/question_lists/{list_id}/questions/{old_question_id}")
async def replace_question_in_list(list_id: str, old_question_id: str, request: Request, user=Depends(authorize(["admin", "setter"]))):
    try:
        body = await request.json()
        
        # Validate list exists
        list_ref = db.collection("question_lists").document(list_id)
        list_doc = list_ref.get()
        if not list_doc.exists:
            raise HTTPException(status_code=404, detail="Question list not found")
        
        list_data = list_doc.to_dict()
        question_ids = list_data.get("questionIds", [])
        
        # Validate old question exists in list
        if old_question_id not in question_ids:
            raise HTTPException(status_code=400, detail="Question not found in this list")
        
        # Create new question in question_bank
        body["createdAt"] = datetime.now(timezone.utc)
        body["createdBy"] = user.get("id")
        body["creatorRole"] = user.get("role")
        
        new_q_ref = db.collection("question_bank").document()
        new_q_ref.set(body)
        new_question_id = new_q_ref.id
        
        # Replace old question ID with new one (maintaining position)
        updated_ids = [new_question_id if qid == old_question_id else qid for qid in question_ids]
        
        list_ref.update({
            "questionIds": updated_ids,
            "updatedAt": datetime.now(timezone.utc)
        })
        
        return {"message": "Question replaced successfully! ✅", "newQuestionId": new_question_id}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to replace question: {str(e)}")

@app.post("/api/exams/{exam_id}/import-question-list/{list_id}")
async def import_question_list_to_exam(exam_id: str, list_id: str, request: Request, user=Depends(authorize(["admin", "setter"]))):
    try:
        print(f"📥 import_question_list_to_exam called: exam_id={exam_id}, list_id={list_id}, user={user.get('name')}")
        
        # Get the exam
        exam_ref = db.collection("exams").document(exam_id)
        exam_doc = exam_ref.get()
        if not exam_doc.exists:
            print(f"❌ Exam not found: {exam_id}")
            raise HTTPException(status_code=404, detail="Exam not found")
        print(f"✅ Exam found: {exam_doc.to_dict().get('title', 'Unknown')}")
        
        # Get the question list with full data
        list_doc = db.collection("question_lists").document(list_id).get()
        if not list_doc.exists:
            print(f"❌ Question list not found: {list_id}")
            raise HTTPException(status_code=404, detail="Question list not found")
        
        list_data = list_doc.to_dict()
        question_ids = list_data.get("questionIds", [])
        print(f"✅ List found: '{list_data.get('name', 'Unknown')}' with {len(question_ids)} question IDs")
        
        if not question_ids:
            print(f"❌ Question list is empty: {list_id}")
            raise HTTPException(status_code=400, detail="Question list is empty")
        
        # Fetch all questions from bank and convert to exam format
        questions_to_add = []
        found_count = 0
        for q_id in question_ids:
            q_doc = db.collection("question_bank").document(q_id).get()
            if q_doc.exists:
                found_count += 1
                q = q_doc.to_dict()
                exam_q = {
                    "subject": q.get("subject", "Physics"),
                    "section": q.get("section", "Single correct answer"),
                    "question": q.get("question", ""),
                    "questionImage": q.get("questionImage", None),
                    "options": q.get("options", []),
                    "optionImages": q.get("optionImages", []),
                    "correctAnswer": (q.get("correctAnswers") or [""])[0] if q.get("correctAnswers") else "",
                    "correctAnswers": q.get("correctAnswers", []),
                    "hint": q.get("hint", ""),
                    "solution": q.get("solution", ""),
                    "solutionImage": q.get("solutionImage", None),
                    "topics": q.get("topics", [])
                }
                questions_to_add.append(exam_q)
        
        print(f"📊 Found {found_count} out of {len(question_ids)} questions in the bank")
        
        # Add to exam
        exam_data = exam_doc.to_dict()
        existing_questions = exam_data.get("questions", [])
        existing_questions.extend(questions_to_add)
        exam_ref.update({"questions": existing_questions})
        
        print(f"✅ Successfully added {len(questions_to_add)} questions to exam")
        
        return {"message": f"{len(questions_to_add)} questions imported from list '{list_data.get('name', '')}'! ✅"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ import_question_list_to_exam error: {str(e)}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to import question list: {str(e)}")

# ==========================================
# 🏆 PUBLIC ROUTES (FOR STUDENTS)
# ==========================================
@app.get("/api/public/exams")
async def get_public_exams():
    docs = db.collection("exams").stream()
    exams_list = []
    
    for doc in docs:
        data = doc.to_dict()
        q_count = len(data.get("questions", []))
        
        exams_list.append({
            "id": doc.id,
            "title": data.get("title", "Untitled Exam"),
            "questionCount": q_count,
            "examType": data.get("examType", data.get("exam_type", "Practice"))
        })
        
    return exams_list

@app.get("/api/public/exams/{exam_id}")
async def get_exam(exam_id: str):
    doc = db.collection("exams").document(exam_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Exam not found")
        
    data = doc.to_dict()
    data["id"] = doc.id
    # Normalize exam type field
    if "exam_type" in data and "examType" not in data:
        data["examType"] = data["exam_type"]
    return data

@app.get("/api/public/results/my-results")
async def get_my_results(user = Depends(authorize(["student"]))):
    try:
        student_name = user.get("name") or user.get("email")
        
        query = db.collection("results").where("studentName", "==", student_name).stream()
        
        results_list = []
        for doc in query:
            data = doc.to_dict()
            
            submitted_time = data.get("submittedAt")
            if submitted_time and hasattr(submitted_time, 'isoformat'):
                time_str = submitted_time.isoformat()
            else:
                time_str = str(submitted_time) if submitted_time else None

            # Smart detection: Check if exam was auto-submitted
            # 1. Check explicit flag
            # 2. Check violation count (>= 3 means auto-submitted)
            # 3. Check away time (>= 300s / 5 min means auto-submitted)
            is_auto_submitted = data.get("autoSubmitted", False)
            
            if not is_auto_submitted:
                violation_count = data.get("violationCount", data.get("totalViolations", 0))
                total_away_time = data.get("totalAwayTime", 0)
                
                # Auto-submitted if max violations reached OR max away time exceeded
                if violation_count >= 3 or total_away_time >= 300:
                    is_auto_submitted = True
            
            # Fallback: if violationCount is 0 but cheatingViolations array has entries, use its length
            violation_count = data.get("violationCount", data.get("totalViolations", 0))
            cheating_violations = data.get("cheatingViolations", [])
            if violation_count == 0 and isinstance(cheating_violations, list) and len(cheating_violations) > 0:
                violation_count = len(cheating_violations)
                if violation_count >= 3:
                    is_auto_submitted = True

            results_list.append({
                "id": doc.id,
                "submittedAt": time_str,
                "autoSubmitted": is_auto_submitted,
                "completed": data.get("completed", False),
                **data
            })
            
        results_list.sort(key=lambda x: x.get("submittedAt") or "", reverse=True)
            
        return results_list
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to fetch your results: {str(e)}")

@app.post("/api/public/exams/save-progress")
async def save_exam_progress(result_payload: dict, user = Depends(authorize(["student"]))):
    """Save/update exam progress for emergency shutdown recovery"""
    student_id = user.get("id")
    exam_id = result_payload.get("examId")
    
    if not exam_id:
        raise HTTPException(status_code=400, detail="examId is required")
    
    try:
        # Extract progress fields directly from payload (not from a nested progressData wrapper)
        progress_data = {
            "studentAnswers": result_payload.get("studentAnswers", {}),
            "statusMap": result_payload.get("statusMap", {}),
            "timeLeft": result_payload.get("timeLeft", 0),
            "currentIdx": result_payload.get("currentIdx", -1),
            "currentSub": result_payload.get("currentSub", "Physics"),
            "questionTimes": result_payload.get("questionTimes", []),
            "subjectTimes": result_payload.get("subjectTimes", {}),
            "violationCount": result_payload.get("violationCount", 0),
            "totalAwayTime": result_payload.get("totalAwayTime", 0),
            "cheatingViolations": result_payload.get("cheatingViolations", []),
            "autoSubmitTriggered": result_payload.get("autoSubmitTriggered", False),
            "requiresAdminResume": result_payload.get("requiresAdminResume", False),
            "autoSubmittedAt": result_payload.get("autoSubmittedAt"),
            "autoSubmitReason": result_payload.get("autoSubmitReason", "")
        }
        
        # Check if progress already exists for this student+exam
        existing_query = db.collection("exam_progress").where("studentId", "==", student_id).where("examId", "==", exam_id).stream()
        existing_doc = None
        for doc in existing_query:
            existing_doc = doc
            break
        
        if existing_doc:
            # Update existing progress
            existing_doc.reference.update({
                **progress_data,
                "updatedAt": datetime.now(timezone.utc)
            })
        else:
            # Create new progress entry
            db.collection("exam_progress").add({
                "studentId": student_id,
                "examId": exam_id,
                **progress_data,
                "createdAt": datetime.now(timezone.utc),
                "updatedAt": datetime.now(timezone.utc)
            })
        
        return {"message": "Progress saved successfully ✅"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save progress: {str(e)}")

@app.get("/api/public/exams/{exam_id}/progress")
async def get_exam_progress(exam_id: str, user = Depends(authorize(["student"]))):
    """Get saved exam progress for emergency recovery"""
    student_id = user.get("id")
    
    try:
        existing_query = db.collection("exam_progress").where("studentId", "==", student_id).where("examId", "==", exam_id).stream()
        for doc in existing_query:
            data = doc.to_dict()
            return {
                "hasProgress": True,
                "updatedAt": data.get("updatedAt"),
                "requiresAdminResume": data.get("requiresAdminResume", False),
                "adminApproved": data.get("adminApproved", False),
                "autoSubmittedAt": data.get("autoSubmittedAt"),
                "autoSubmitReason": data.get("autoSubmitReason", ""),
                "resumedAt": data.get("resumedAt"),
                "resumedBy": data.get("resumedBy"),
                "studentAnswers": data.get("studentAnswers", {}),
                "statusMap": data.get("statusMap", {}),
                "timeLeft": data.get("timeLeft", 0),
                "currentIdx": data.get("currentIdx", -1),
                "currentSub": data.get("currentSub", "Physics"),
                "questionTimes": data.get("questionTimes", []),
                "subjectTimes": data.get("subjectTimes", {}),
                "violationCount": data.get("violationCount", 0),
                "totalAwayTime": data.get("totalAwayTime", 0),
                "cheatingViolations": data.get("cheatingViolations", []),
                "autoSubmitTriggered": data.get("autoSubmitTriggered", False)
            }
        
        return {"hasProgress": False}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch progress: {str(e)}")

@app.get("/api/public/exams/{exam_id}/resume-status")
async def get_exam_resume_status(exam_id: str, user = Depends(authorize(["student"]))):
    """Check if the student can resume an exam without admin approval.
    
    Returns:
    - canResume: True if the student can resume the exam
    - requiresAdmin: True if admin approval is needed before resuming
    - adminApproved: True if admin has already approved the resume
    - reason: Human-readable explanation
    """
    student_id = user.get("id")
    
    try:
        existing_query = db.collection("exam_progress").where("studentId", "==", student_id).where("examId", "==", exam_id).stream()
        for doc in existing_query:
            data = doc.to_dict()
            requires_admin = data.get("requiresAdminResume", False)
            admin_approved = data.get("adminApproved", False)
            
            if requires_admin and not admin_approved:
                return {
                    "canResume": False,
                    "requiresAdmin": True,
                    "adminApproved": False,
                    "reason": "This exam was auto-submitted due to integrity violations. An admin must approve the resume before you can continue."
                }
            
            return {
                "canResume": True,
                "requiresAdmin": requires_admin,
                "adminApproved": admin_approved,
                "reason": "You can resume this exam."
            }
        
        return {
            "canResume": True,
            "requiresAdmin": False,
            "adminApproved": False,
            "reason": "No saved progress found. You can start fresh."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check resume status: {str(e)}")

@app.delete("/api/public/exams/{exam_id}/progress")
async def delete_exam_progress(exam_id: str, user = Depends(authorize(["student"]))):
    """Delete saved exam progress after submission"""
    student_id = user.get("id")
    
    try:
        existing_query = db.collection("exam_progress").where("studentId", "==", student_id).where("examId", "==", exam_id).stream()
        for doc in existing_query:
            doc.reference.delete()
        
        return {"message": "Progress deleted ✅"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete progress: {str(e)}")

@app.post("/api/admin/results/{result_id}/finish")
async def finish_result(result_id: str, user = Depends(authorize(["admin"]))):
    """Finalize an auto-submitted result by clearing saved progress and marking completed"""
    try:
        # Get the result document
        result_ref = db.collection("results").document(result_id)
        result_doc = result_ref.get()
        
        if not result_doc.exists:
            raise HTTPException(status_code=404, detail="Result not found")
        
        result_data = result_doc.to_dict()
        student_id = result_data.get("studentId")
        exam_id = result_data.get("examId")
        
        # Delete any saved exam progress for this student+exam
        if student_id and exam_id:
            progress_query = db.collection("exam_progress").where("studentId", "==", student_id).where("examId", "==", exam_id).stream()
            for doc in progress_query:
                doc.reference.delete()
        
        # Mark the result as completed (finalized)
        result_ref.update({
            "completed": True,
            "completedAt": datetime.now(timezone.utc),
            "completedBy": user.get("id")
        })
        
        return {"message": "Result finalized successfully ✅"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to finish result: {str(e)}")

@app.post("/api/public/exams/submit")
async def submit_exam(request: Request, user = Depends(authorize(["student"]))):
    """Submit exam answers and calculate score"""
    try:
        body = await request.json()
        exam_id = body.get("examId")
        student_answers = body.get("studentAnswers", {})
        status_map = body.get("statusMap", {})
        time_left = body.get("timeLeft", 0)
        question_times = body.get("questionTimes", [])
        subject_times = body.get("subjectTimes", {})
        answer_images = body.get("answerImages", {})
        
        # Accept both field name conventions for robustness
        violation_count = body.get("violationCount", body.get("totalViolations", 0))
        total_away_time = body.get("totalAwayTime", 0)
        cheating_violations = body.get("cheatingViolations", [])
        auto_submit_triggered = body.get("autoSubmitTriggered", body.get("autoSubmitted", False))
        auto_submit_reason = body.get("autoSubmitReason", "")
        
        if not exam_id:
            raise HTTPException(status_code=400, detail="examId is required")
        
        # Fetch exam data
        exam_doc = db.collection("exams").document(exam_id).get()
        if not exam_doc.exists:
            raise HTTPException(status_code=404, detail="Exam not found")
        
        exam_data = exam_doc.to_dict()
        questions = exam_data.get("questions", [])
        
        # Calculate score (only for MCQ/auto-graded questions)
        total_score = 0
        correct_count = 0
        incorrect_count = 0
        not_attempted_count = 0
        subject_wise = {}
        
        for i, q in enumerate(questions):
            q_id = str(i)
            student_ans = student_answers.get(q_id)
            correct_ans = q.get("correctAnswer", "")
            subject = q.get("subject", "Unknown")
            question_type = q.get("questionType", "mcq")
            marks = q.get("marks", 1)
            
            if subject not in subject_wise:
                subject_wise[subject] = {
                    "score": 0,
                    "correct": 0,
                    "incorrect": 0,
                    "notAttempted": 0,
                    "subjectTotalMarks": 0
                }
            
            # Add marks to total
            subject_wise[subject]["subjectTotalMarks"] += marks
            
            # For subjective questions, don't auto-grade (marks will be assigned by admin)
            if question_type in ["subjective", "case-based"] or marks > 1:
                if student_ans is not None and student_ans != "":
                    # Question attempted but not auto-graded
                    not_attempted_count += 1
                    subject_wise[subject]["notAttempted"] += 1
                else:
                    not_attempted_count += 1
                    subject_wise[subject]["notAttempted"] += 1
            else:
                # MCQ - auto grade
                if student_ans is None or student_ans == "":
                    not_attempted_count += 1
                    subject_wise[subject]["notAttempted"] += 1
                elif student_ans == correct_ans:
                    total_score += marks
                    correct_count += 1
                    subject_wise[subject]["score"] += marks
                    subject_wise[subject]["correct"] += 1
                else:
                    total_score -= 1  # Negative marking only for MCQs
                    incorrect_count += 1
                    subject_wise[subject]["score"] -= 1
                    subject_wise[subject]["incorrect"] += 1
        
        # Calculate total marks possible
        total_marks_possible = sum(q.get("marks", 1) for q in questions)
        
        # Prepare result data
        result_data = {
            "studentId": user.get("id"),
            "studentName": user.get("name") or user.get("email"),
            "examId": exam_id,
            "examTitle": exam_data.get("title", "Untitled Exam"),
            "examQuestionsCount": len(questions),
            "totalScore": total_score,
            "totalMarksPossible": total_marks_possible,
            "correctCount": correct_count,
            "incorrectCount": incorrect_count,
            "notAttemptedCount": not_attempted_count,
            "subjectWiseBreakdown": subject_wise,
            "studentAnswers": student_answers,
            "answerImages": answer_images,
            "statusMap": status_map,
            "timeLeft": time_left,
            "questionTimes": question_times,
            "subjectTimes": subject_times,
            "violationCount": violation_count,
            "totalAwayTime": total_away_time,
            "cheatingViolations": cheating_violations,
            "autoSubmitted": auto_submit_triggered,
            "autoSubmitReason": auto_submit_reason,
            "submittedAt": datetime.now(timezone.utc)
        }
        
        # Save result
        db.collection("results").add(result_data)
        
        # Delete saved progress ONLY for normal (non-auto) submissions.
        # For auto-submitted exams (integrity violations), keep the progress
        # so an admin can resume the exam for the candidate later.
        if not auto_submit_triggered:
            try:
                existing_query = db.collection("exam_progress").where("studentId", "==", user.get("id")).where("examId", "==", exam_id).stream()
                for doc in existing_query:
                    doc.reference.delete()
            except:
                pass
        else:
            # Auto-submitted due to integrity violations - mark progress as
            # requiring admin approval before the student can resume.
            try:
                existing_query = db.collection("exam_progress").where("studentId", "==", user.get("id")).where("examId", "==", exam_id).stream()
                for doc in existing_query:
                    doc.reference.update({
                        "requiresAdminResume": True,
                        "adminApproved": False,
                        "autoSubmittedAt": datetime.now(timezone.utc),
                        "autoSubmitReason": auto_submit_reason or "Integrity violation",
                        "updatedAt": datetime.now(timezone.utc)
                    })
            except Exception as e:
                print(f"⚠️ Could not mark progress as requiring admin resume: {e}")
        
        return {
            "message": "Exam submitted successfully! ✅",
            "totalScore": total_score,
            "correctCount": correct_count,
            "incorrectCount": incorrect_count,
            "notAttemptedCount": not_attempted_count
        }
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to submit exam: {str(e)}")

@app.get("/api/public/results/{result_id}/analysis")
async def get_result_analysis(result_id: str, user = Depends(authorize(["admin", "setter", "student"]))):
    """Get detailed analysis for a result including rankings"""
    try:
        result_doc = db.collection("results").document(result_id).get()
        if not result_doc.exists:
            raise HTTPException(status_code=404, detail="Result not found")
        
        result_data = result_doc.to_dict()
        exam_id = result_data.get("examId")
        
        if not exam_id:
            raise HTTPException(status_code=400, detail="Exam ID not found in result")
        
        # Smart detection: Check if exam was auto-submitted
        # 1. Check explicit flag
        # 2. Check violation count (>= 3 means auto-submitted)
        # 3. Check away time (>= 300s / 5 min means auto-submitted)
        is_auto_submitted = result_data.get("autoSubmitted", False)
        
        if not is_auto_submitted:
            violation_count = result_data.get("violationCount", result_data.get("totalViolations", 0))
            total_away_time = result_data.get("totalAwayTime", 0)
            
            # Auto-submitted if max violations reached OR max away time exceeded
            if violation_count >= 3 or total_away_time >= 300:
                is_auto_submitted = True
        
        # Fallback: if violationCount is 0 but cheatingViolations array has entries, use its length
        violation_count = result_data.get("violationCount", result_data.get("totalViolations", 0))
        cheating_violations = result_data.get("cheatingViolations", [])
        if violation_count == 0 and isinstance(cheating_violations, list) and len(cheating_violations) > 0:
            violation_count = len(cheating_violations)
            if violation_count >= 3:
                is_auto_submitted = True
        
        # Get all results for this exam to calculate rankings
        all_results = db.collection("results").where("examId", "==", exam_id).stream()
        
        scores = []
        subject_scores = {}
        
        for doc in all_results:
            data = doc.to_dict()
            score = data.get("totalScore", 0)
            scores.append(score)
            
            # Collect subject-wise scores
            swb = data.get("subjectWiseBreakdown", {})
            for subject, stats in swb.items():
                if subject not in subject_scores:
                    subject_scores[subject] = []
                subject_scores[subject].append(stats.get("score", 0))
        
        # Calculate overall rank
        my_score = result_data.get("totalScore", 0)
        scores.sort(reverse=True)
        overall_rank = 1
        for s in scores:
            if s > my_score:
                overall_rank += 1
        
        # Calculate subject ranks
        subject_ranks = {}
        for subject, sub_scores in subject_scores.items():
            sub_scores.sort(reverse=True)
            my_sub_score = result_data.get("subjectWiseBreakdown", {}).get(subject, {}).get("score", 0)
            rank = 1
            for s in sub_scores:
                if s > my_sub_score:
                    rank += 1
            avg = sum(sub_scores) / len(sub_scores) if sub_scores else 0
            subject_ranks[subject] = {
                "rank": rank,
                "avg": round(avg, 1),
                "top": max(sub_scores) if sub_scores else 0,
                "myScore": my_sub_score
            }
        
        # Build question analysis
        exam_doc = db.collection("exams").document(exam_id).get()
        questions = exam_doc.to_dict().get("questions", []) if exam_doc.exists else []
        
        question_analysis = []
        student_answers = result_data.get("studentAnswers", {})
        answer_images = result_data.get("answerImages", {})
        question_times = result_data.get("questionTimes", [])
        subjective_marks = result_data.get("subjectiveMarks", {})
        
        for i, q in enumerate(questions):
            q_id = str(i)
            student_ans = student_answers.get(q_id)
            correct_ans = q.get("correctAnswer", "")
            is_attempted = student_ans is not None and student_ans != ""
            is_correct = is_attempted and student_ans == correct_ans
            
            time_spent = None
            if i < len(question_times):
                time_spent = question_times[i]
            
            # Get awarded marks for subjective questions
            awarded_marks = subjective_marks.get(str(i))
            
            question_analysis.append({
                "question": q.get("question", ""),
                "questionImage": q.get("questionImage"),
                "options": q.get("options", []),
                "optionImages": q.get("optionImages", []),
                "correctAnswer": correct_ans,
                "studentAnswer": student_ans if is_attempted else None,
                "isAttempted": is_attempted,
                "isCorrect": is_correct,
                "subject": q.get("subject", "Unknown"),
                "topics": q.get("topics", []),
                "timeSpent": time_spent,
                "solution": q.get("solution", ""),
                "solutionImage": q.get("solutionImage"),
                "questionType": q.get("questionType", "mcq"),
                "marks": q.get("marks", 1),
                "answerImage": answer_images.get(str(i)),
                "awardedMarks": awarded_marks
            })
        
        return {
            "overall": {
                "myScore": my_score,
                "rank": overall_rank,
                "top": max(scores) if scores else 0,
                "totalStudents": len(scores)
            },
            "subjects": subject_ranks,
            "subjectTimes": result_data.get("subjectTimes", {}),
            "questionAnalysis": question_analysis,
            "totalStudents": len(scores),
            "cheatingViolations": cheating_violations,
            "totalViolations": violation_count,
            "totalAwayTime": result_data.get("totalAwayTime", 0),
            "autoSubmitted": is_auto_submitted,
            "autoSubmitReason": result_data.get("autoSubmitReason", "")
        }
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to fetch analysis: {str(e)}")

@app.get("/api/results")
async def get_all_results(user=Depends(authorize(["admin"]))):
    """Get all exam results for admin view"""
    try:
        docs = db.collection("results").order_by("submittedAt", direction=firestore.Query.DESCENDING).stream()
        results = []
        for doc in docs:
            data = doc.to_dict()
            
            # Smart detection: Check if exam was auto-submitted
            # 1. Check explicit flag (new feature)
            # 2. Check violation count (>= 3 means auto-submitted)
            # 3. Check away time (>= 300s / 5 min means auto-submitted)
            is_auto_submitted = data.get("autoSubmitted", False)
            
            # If not explicitly marked, check violation patterns
            if not is_auto_submitted:
                violation_count = data.get("violationCount", data.get("totalViolations", 0))
                total_away_time = data.get("totalAwayTime", 0)
                
                # Auto-submitted if max violations reached OR max away time exceeded
                if violation_count >= 3 or total_away_time >= 300:
                    is_auto_submitted = True
            
            results.append({
                "id": doc.id,
                "studentName": data.get("studentName", "Unknown"),
                "examTitle": data.get("examTitle", "Unknown"),
                "totalScore": data.get("totalScore", 0),
                "submittedAt": data.get("submittedAt"),
                "autoSubmitted": is_auto_submitted,
                "completed": data.get("completed", False)
            })
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch results: {str(e)}")

@app.post("/api/admin/results/{result_id}/resume")
async def resume_exam(result_id: str, user=Depends(authorize(["admin"]))):
    """Resume an auto-submitted exam by deleting the result and keeping progress"""
    try:
        # Get the result document
        result_ref = db.collection("results").document(result_id)
        result_doc = result_ref.get()
        
        if not result_doc.exists:
            raise HTTPException(status_code=404, detail="Result not found")
        
        result_data = result_doc.to_dict()
        
        # Smart detection: Check if exam was auto-submitted
        is_auto_submitted = result_data.get("autoSubmitted", False)
        
        # If not explicitly marked, check violation patterns
        if not is_auto_submitted:
            violation_count = result_data.get("violationCount", result_data.get("totalViolations", 0))
            total_away_time = result_data.get("totalAwayTime", 0)
            
            # Auto-submitted if max violations reached OR max away time exceeded
            if violation_count >= 3 or total_away_time >= 300:
                is_auto_submitted = True
        
        # Check if it was auto-submitted
        if not is_auto_submitted:
            raise HTTPException(status_code=400, detail="Only auto-submitted exams can be resumed")
        
        student_id = result_data.get("studentId")
        exam_id = result_data.get("examId")
        
        # Delete the result document
        result_ref.delete()
        
        # Note: We keep the exam_progress intact so student can resume
        # The progress is already saved in the exam_progress collection
        
        # Mark the progress as resumed by admin for auditability
        # Set adminApproved=True and requiresAdminResume=False so the student
        # can now resume the exam without any further admin intervention.
        try:
            progress_query = db.collection("exam_progress").where("studentId", "==", student_id).where("examId", "==", exam_id).stream()
            for doc in progress_query:
                doc.reference.update({
                    "resumedAt": datetime.now(timezone.utc),
                    "resumedBy": user.get("id") or "admin",
                    "adminApproved": True,
                    "requiresAdminResume": False
                })
        except Exception as e:
            print(f"⚠️ Could not mark progress as resumed: {e}")
        
        return {
            "message": "Exam resumed successfully! The student can now continue the exam from where they left off. ✅",
            "studentId": student_id,
            "examId": exam_id
        }
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to resume exam: {str(e)}")

# ==========================================
# 📁 STATIC FILES SERVING
# ==========================================
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

# ==========================================
# 📝 CBSE EXAM SUPPORT - MANUAL EVALUATION
# ==========================================

@app.post("/api/admin/results/{result_id}/update-marks")
async def update_subjective_marks(result_id: str, request: Request, user=Depends(authorize(["admin"]))):
    """Update marks for subjective questions in a result"""
    try:
        body = await request.json()
        subjective_marks = body.get("subjectiveMarks", {})
        
        result_ref = db.collection("results").document(result_id)
        result_doc = result_ref.get()
        
        if not result_doc.exists:
            raise HTTPException(status_code=404, detail="Result not found")
        
        # Update the result with subjective marks
        result_ref.update({
            "subjectiveMarks": subjective_marks,
            "manuallyEvaluated": True,
            "evaluatedBy": user.get("id"),
            "evaluatedAt": datetime.now(timezone.utc)
        })
        
        return {"message": "Marks updated successfully! ✅"}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to update marks: {str(e)}")

@app.post("/api/public/exams/{exam_id}/upload-answer")
async def upload_answer_image(exam_id: str, request: Request, user = Depends(authorize(["student"]))):
    """Upload answer image for subjective questions"""
    try:
        body = await request.json()
        question_index = body.get("questionIndex")
        image_data = body.get("imageData")  # Base64 encoded image
        
        if question_index is None or not image_data:
            raise HTTPException(status_code=400, detail="questionIndex and imageData are required")
        
        # Store in exam_progress
        student_id = user.get("id")
        
        progress_query = db.collection("exam_progress").where("studentId", "==", student_id).where("examId", "==", exam_id).stream()
        progress_doc = None
        for doc in progress_query:
            progress_doc = doc
            break
        
        if progress_doc:
            # Update existing progress with answer image
            progress_data = progress_doc.to_dict()
            answer_images = progress_data.get("answerImages", {})
            answer_images[str(question_index)] = image_data
            
            progress_doc.reference.update({
                "answerImages": answer_images,
                "updatedAt": datetime.now(timezone.utc)
            })
        else:
            # Create new progress entry with answer image
            db.collection("exam_progress").add({
                "studentId": student_id,
                "examId": exam_id,
                "answerImages": {str(question_index): image_data},
                "createdAt": datetime.now(timezone.utc),
                "updatedAt": datetime.now(timezone.utc)
            })
        
        return {"message": "Answer image uploaded successfully! ✅"}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to upload answer image: {str(e)}")
