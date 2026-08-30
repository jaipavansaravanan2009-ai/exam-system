import io, re, os

files = [
    r'd:\Desktop\exam-system\frontend\admin.html',
    r'd:\Desktop\exam-system\frontend\student_portal.html',
    r'd:\Desktop\exam-system\frontend\take_exam.html',
]

for path in files:
    with io.open(path, 'r', encoding='utf-8') as f:
        html = f.read()
    # Extract inline script blocks (no src=)
    blocks = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', html, re.DOTALL)
    name = os.path.basename(path).replace('.html', '')
    out_name = f'_check_{name}.js'
    combined = '\n// =================\n'.join(blocks)
    combined = '(function(){\n' + combined + '\n})();\n'
    with io.open(os.path.join(r'd:\Desktop\exam-system', out_name), 'w', encoding='utf-8') as f:
        f.write(combined)
    print(f"{name}: extracted {len(blocks)} inline script blocks -> {out_name}")