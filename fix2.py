import pathlib

path = 'd:/Desktop/exam-system/main.py'
c = pathlib.Path(path).read_text(encoding='utf-8')

# 2) Keep exam_progress for normal submissions too
old_normal_delete = '''        # Delete saved progress ONLY for normal (non-auto) submissions.
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
'''

new_keep_progress = '''        # Keep exam_progress for all submissions so admin can review answer images
        # For auto-submitted exams, also mark as requiring admin approval before resume
        try:
            existing_query = db.collection("exam_progress").where("studentId", "==", user.get("id")).where("examId", "==", exam_id).stream()
            for doc in existing_query:
                if auto_submit_triggered:
                    doc.reference.update({
                        "requiresAdminResume": True,
                        "adminApproved": False,
                        "autoSubmittedAt": datetime.now(timezone.utc),
                        "autoSubmitReason": auto_submit_reason or "Integrity violation",
                        "updatedAt": datetime.now(timezone.utc)
                    })
                else:
                    doc.reference.update({
                        "submittedAt": datetime.now(timezone.utc),
                        "updatedAt": datetime.now(timezone.utc)
                    })
        except Exception as e:
            print(f"⚠️ Could not update exam progress: {e}")
'''

c = c.replace(old_normal_delete, new_keep_progress)

# 3) Update analysis endpoint to fetch answerImages from exam_progress as fallback
old_analysis_images = '''        student_answers = result_data.get("studentAnswers", {})
        answer_images = result_data.get("answerImages", {})
        awarded_marks_map = result_data.get("subjectiveMarks", {}) or {}
'''

new_analysis_images = '''        student_answers = result_data.get("studentAnswers", {})
        answer_images = result_data.get("answerImages", {})
        # Fallback: fetch answerImages from exam_progress if not in result (to avoid 1MB Firestore limit)
        if not answer_images:
            try:
                progress_query = db.collection("exam_progress").where("studentId", "==", result_data.get("studentId")).where("examId", "==", exam_id).stream()
                for pdoc in progress_query:
                    pdata = pdoc.to_dict()
                    answer_images = pdata.get("answerImages", {}) or {}
                    break
            except Exception as e:
                print(f"⚠️ Could not fetch answer images from exam_progress: {e}")
        awarded_marks_map = result_data.get("subjectiveMarks", {}) or {}
'''

c = c.replace(old_analysis_images, new_analysis_images)

# 4) Also update the other answer_images fetch in update-marks endpoint
old_update_marks_images = '''        # Recompute the full score (auto-graded + admin-awarded subjective marks)
        student_answers = result_data.get("studentAnswers", {})
        answer_images = result_data.get("answerImages", {})
        exam_type = result_data.get("examType", "")
        grading = compute_exam_score(questions, student_answers, answer_images, exam_type)
'''

new_update_marks_images = '''        # Recompute the full score (auto-graded + admin-awarded subjective marks)
        student_answers = result_data.get("studentAnswers", {})
        answer_images = result_data.get("answerImages", {})
        # Fallback: fetch answerImages from exam_progress if not in result
        if not answer_images:
            try:
                progress_query = db.collection("exam_progress").where("studentId", "==", result_data.get("studentId")).where("examId", "==", result_data.get("examId")).stream()
                for pdoc in progress_query:
                    pdata = pdoc.to_dict()
                    answer_images = pdata.get("answerImages", {}) or {}
                    break
            except Exception as e:
                print(f"⚠️ Could not fetch answer images from exam_progress: {e}")
        exam_type = result_data.get("examType", "")
        grading = compute_exam_score(questions, student_answers, answer_images, exam_type)
'''

c = c.replace(old_update_marks_images, new_update_marks_images)

pathlib.Path(path).write_text(c, encoding='utf-8')
print('Done fixing Firestore document size issue')