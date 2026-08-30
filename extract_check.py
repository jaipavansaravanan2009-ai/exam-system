import io, re

# Extract the viewAdminAnalysis + helpers from admin.html and syntax check
with io.open(r'd:\Desktop\exam-system\frontend\admin.html', 'r', encoding='utf-8') as f:
    html = f.read()

start = html.index('async function viewAdminAnalysis(resultId)')
# End after toggleQuestionAnalysis closing brace
marker = '    // ================= QUESTION LIST FUNCTIONS ================='
end = html.index(marker)
segment = html[start:end]

# Wrap in async context so node accepts top-level function (non-async functions are fine)
out = '(() => {\n' + segment + '\n})();\n'
with io.open(r'd:\Desktop\exam-system\_check_admin.js', 'w', encoding='utf-8') as f:
    f.write(out)
print(f"Extracted {len(segment)} chars cleanly.")