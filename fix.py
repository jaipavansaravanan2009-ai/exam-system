import pathlib

path = 'd:/Desktop/exam-system/main.py'
c = pathlib.Path(path).read_text(encoding='utf-8')

c = c.replace('"answerImages": answer_images,','')

pathlib.Path(path).write_text(c, encoding='utf-8')
print('ok')