def hello():
    f = open("/home/pyronia/hello.txt", "r")
    lines = f.readlines()
    f.close()
    return lines

def add_line(msg_lines):
    print("msg_lines addr: "+str(hex(id(msg_lines))))
    msg_lines.append(", world")

text = hello()
print("text addr: "+str(hex(id(text))))
add_line(text)
print("text addr after: "+str(hex(id(text))))
print("".join(text))
