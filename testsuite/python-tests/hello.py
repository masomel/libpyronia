from message import Message

def hello():
    f = open("/home/pyronia/hello.txt", "r")
    lines = f.readlines()
    f.close()
    return lines[0].strip()
    #return lines
    #return { 'greeting' : lines[0].strip() }
    #return Message(lines[0].strip())

def add_line(msg):
    print("msg addr: "+str(hex(id(msg))))
    #msg.append("world")
    #msg['name'] = "world"
    msg.set_name("world")

line = hello()
text = Message(line)
#print(", ".join(text))
#print(text['greeting']+", "+text['name'])
text.set_name("world")
#add_line(text)
text.print_msg()
