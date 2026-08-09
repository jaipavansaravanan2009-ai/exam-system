f = r'd:\Desktop\exam-system\frontend\take_exam.html'
with open(f, 'r', encoding='utf-8') as fh:
    lines = fh.readlines()

# Fix blur comment indentation (line 673, 0-indexed 672): 16 spaces -> 4 spaces
for i, line in enumerate(lines):
    if '// Detect window blur (Alt+Tab, clicking taskbar, etc.)' in line and line.startswith(' ' * 16):
        lines[i] = '    // Detect window blur (Alt+Tab, clicking taskbar, etc.)\n'
        break

# Fix trailing whitespace and extra blank lines after focus handler
for i in range(len(lines)):
    # Fix trailing whitespace on lines that are just spaces
    if lines[i].strip() == '' and i > 690 and i < 695:
        lines[i] = '\n'

# Remove extra blank line between focus handler and fullscreen detection
for i in range(len(lines) - 1):
    if (lines[i].strip() == '' and i > 690 and i < 695
        and i + 1 < len(lines) and '// Fullscreen change detection' in lines[i + 1]):
        del lines[i]
        break

with open(f, 'w', encoding='utf-8') as fh:
    fh.writelines(lines)

print('Fixed indentation and blank lines')