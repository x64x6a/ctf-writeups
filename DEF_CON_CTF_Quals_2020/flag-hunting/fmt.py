"""
Used this to indent function calls to assist in reversing by hand
"""
with open('trace.txt','rb') as f:
    trace = f.read()


out = ''
indents = 0
for line in trace.split('\n'):
    new_line = "|   "*indents + line + "\n"
    if "call" in line:
        indents += 1
    elif "ret" in line:
        indents -= 1
        if indents < 0:
            indents = 0
    out += new_line
print out
