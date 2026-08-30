# -*- coding: utf-8 -*-
"""
Apply residual result-analysis fixes.

1) main.py  /api/exams/{id}/bulk-upload-zip  (exam ZIP / CSV import)
   -> preserve Hint, Solution, SolutionImage CSV columns so JEE papers
      uploaded directly into an exam keep hints + detailed solutions.
2) main.py  /api/public/results/{id}/analysis
   -> expose studentName so the admin analysis modal can name the candidate.
3) Admin analysis modal header shows the real candidate name.
   Synced across frontend/admin.html, _check_admin.js, new_admin_analysis.js.
"""
import re


def read(path):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        return f.read()


def write(path, text):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(text)


def replace_once(text, pattern, repl, tag, count_expected=1):
    new, n = re.subn(pattern, repl, text)
    if n != count_expected:
        raise SystemExit(
            f"FAIL [{tag}]: expected {count_expected} replacement(s), got {n}")
    print(f"OK [{tag}]: replaced {n} occurrence(s)")
    return new


# ---- 1) bulk_upload_zip: keep hint/solution/solutionImage ----------------
p = 'main.py'
t = read(p)
pat1 = re.compile(
    r'"correctAnswer": correct_ans,(?P<nl1>\r?\n)(?P<ind1>[ \t]+)'
    r'"correctAnswers": correct_answers_list,(?P<nl2>\r?\n)(?P<ind2>[ \t]+)'
    r'"questionType": q_type_csv,(?P<nl3>\r?\n)(?P<ind3>[ \t]+)"marks": marks_val,'
)
rep1 = (
    r'"correctAnswer": correct_ans,\g<nl1>\g<ind1>'
    r'"correctAnswers": correct_answers_list,\g<nl2>\g<ind2>'
    r'"questionType": q_type_csv,\g<nl3>\g<ind3>"marks": marks_val,'
    r'\g<nl3>\g<ind3>"hint": get_val(row, ["Hint", "hint"]),'
    r'\g<nl3>\g<ind3>"solution": get_val(row, ["Solution", "solution"]),'
    r'\g<nl3>\g<ind3>"solutionImage": get_img(row, '
    r'["SolutionImage", "Solution_Image", "SolutionImageURL"]),'
)
t = replace_once(t, pat1, rep1,
                 'main.py bulk_upload_zip hint/solution')

# ---- 2) analysis response exposes studentName -----------------------------
pat2 = re.compile(r'(?P<nl>\r?\n)(?P<ind>[ \t]*)"subjects": subject_ranks,')
rep2 = (
    r'\g<nl>\g<ind>"studentName": result_data.get("studentName", ""),'
    r'\g<nl>\g<ind>"subjects": subject_ranks,'
)
t = replace_once(t, pat2, rep2, 'main.py analysis studentName')
write(p, t)

# ---- 3) candidate header in the admin analysis modal ----------------------
cand_pat = re.compile(r"\$\{analysisData\.overall \? 'Student' : 'Unknown'\}")
cand_rep = "${analysisData.studentName || 'Student'}"
for p in ('frontend/admin.html', '_check_admin.js', 'new_admin_analysis.js'):
    t = read(p)
    t = replace_once(t, cand_pat, cand_rep, f'{p} candidate header')
    write(p, t)

print('ALL PATCHES APPLIED OK')