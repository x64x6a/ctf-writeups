

class node():
    def __init__(self, value):
        self.value = value
        self.count = 1
        self.indexes = [value]
        self.flag = 1
        self.left = None
        self.right = None

        self.char = '?'

    def __str__(self):
        return str(self.indexes)


def print_tree(n, depth=0, notes=''):
    if n == None:
        return
    prepend = '|    '*(depth)
    v = str(n.indexes)
    print prepend + notes+v
    depth += 1
    print_tree(n.left, depth, notes='left-')
    print_tree(n.right, depth, notes='right-')

def get_nodes(n):
    dt = {}
    for i in n.indexes:
        dt[i] = n

    if n.left:
        res = get_nodes(n.left)
        for k in res:
            dt[k] = res[k]

    if n.right:
        res = get_nodes(n.right)
        for k in res:
            dt[k] = res[k]
    return dt

def get_flag(nodes):
    flag = ''
    for i in range(len(nodes)):
        flag += nodes[i].char
    return flag + '}'


def fix_left(root):
    a = root
    if a.left and a.left.flag == a.flag:
        b = a.left
        a.left = b.right
        b.right = a
        a = b
    return a

def fix_right(root):
    a = root
    if a.right and a.right.right and a.right.right.flag == a.flag:
        b = a.right
        a.right = b.left
        b.left = a
        b.flag += 1
        a = b
    return a

def add_node(code, root, e):
    current_jmp  = ''
    depth = 0
    jmps = []
    for i in range(len(code)):
        line = code[i]
        if 'jne    0x55555555497c' in line:
            current_jmp = ''
            jmps.append(current_jmp)
        elif 'jne    0x55555555499d' in line:
            current_jmp = 'jne'
            jmps.append(current_jmp)
        elif 'jge    0x5555555549ce' in line:
            current_jmp = 'jge'
            jmps.append(current_jmp)
        elif 'jle    0x5555555549fd' in line:
            current_jmp = 'jle'
            jmps.append(current_jmp)
        elif 'call' in line:
            break
    if jmps[-1] == '':
        n = node(e)
    elif jmps[-1] == 'jne':
        root.count += 1
        root.indexes.append(e)
        n = fix_right(fix_left(root))
    elif jmps[-1] == 'jge':
        n = add_node(code[i + 1:], root.left, e)
        root.left = n
        n = fix_right(fix_left(root))
    elif jmps[-1] == 'jle':
        n = add_node(code[i + 1:], root.right, e)
        root.right = n
        n = fix_right(fix_left(root))
    return n



def main():
    with open('trace.txt','rb') as f:
        trace = f.read()


    func_calls = []

    func_call = []
    append = False
    for line in trace.split('\n'):
        if not line:
            continue
        if "ac04e8a47e020e42aae3c139ba59f49b" in line:
            append = False
            func_calls.append(func_call)
            func_call = []
        elif append:
            func_call.append(line)
        elif "ca5ab312e8886c46a899368f61547e0b" in line:
            append = True

    indexes = []
    func_addr = "0x555555554954"
    arr = []
    root = None
    for i,func in enumerate(func_calls):
        root = add_node(func, root, i)


    """Tree looks like this:
[7, 33]
|    left-[4, 6, 15, 16, 19, 36, 56]
|    |    left-[0, 1, 2]
|    |    |    left-[8, 11, 17, 22, 26, 30, 34, 39, 44, 51]
|    |    |    right-[27]
|    |    |    |    left-[20, 32, 37, 54]
|    |    |    |    right-[31, 55]
|    |    |    |    |    right-[25, 38, 50]
|    |    right-[24]
|    |    |    left-[13, 41]
|    |    |    |    right-[42, 49]
|    |    |    right-[9]
|    right-[12, 40, 46, 52]
|    |    left-[14, 21, 35, 53]
|    |    |    left-[23, 28]
|    |    |    |    right-[48]
|    |    |    right-[43, 45]
|    |    right-[5]
|    |    |    left-[47]
|    |    |    right-[10, 18, 29]
|    |    |    |    right-[3]
"""

    nodes = get_nodes(root)

    # set knowns
    nodes[0].char = 'O'
    nodes[3].char = '{'
    nodes[8].char = ' '

    # start guessing.. starting with 'abc..' and adjusting from there
    nodes[20].char = 'a'
    nodes[27].char = 'b'
    nodes[31].char = 'c'
    nodes[25].char = 'd'
    nodes[4].char = 'e'

    nodes[13].char = 'h'
    nodes[42].char = 'i'
    nodes[24].char = 'l'
    nodes[9].char = 'm'

    nodes[7].char = 'n'
    nodes[23].char = 'o'
    nodes[48].char = 'p'

    nodes[14].char = 'r'
    nodes[43].char = 's'
    nodes[12].char = 't'
    

    nodes[47].char = 'u'
    nodes[5].char = 'v'
    nodes[10].char = 'y'

    print get_flag(nodes)

if __name__ == '__main__':
    main()



"""
OOO{even my three year old boy can read this stupid trace}
"""