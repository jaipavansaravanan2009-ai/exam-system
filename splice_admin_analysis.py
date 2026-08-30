import io

# Read admin.html
with io.open(r'd:\Desktop\exam-system\frontend\admin.html', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Verify boundaries
assert 'async function viewAdminAnalysis(resultId)' in lines[2760], f"Line 2761 mismatch: {lines[2760][:80]!r}"
assert lines[3158].strip() == '}', f"Line 3159 mismatch: {lines[3158][:80]!r}"
print("Boundaries verified.")

# Read new function content
with io.open(r'd:\Desktop\exam-system\new_admin_analysis.js', 'r', encoding='utf-8') as f:
    new_content = f.read()

# Preserve indentation: the new content lines already carry their own indent.
new_lines = new_content.splitlines(keepends=True)
if new_lines and not new_lines[-1].endswith('\n'):
    new_lines[-1] += '\n'

# Replace lines 2761..3159 (0-based 2760..3158)
replacement = lines[:2760] + new_lines + lines[3159:]
with io.open(r'd:\Desktop\exam-system\frontend\admin.html', 'w', encoding='utf-8', newline='') as f:
    f.writelines(replacement)

print(f"Replaced lines 2761-3159 with {len(new_lines)} new lines.")
print(f"Old file lines: {len(lines)} -> New file lines: {len(replacement)}")
