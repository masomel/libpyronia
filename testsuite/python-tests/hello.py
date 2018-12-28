def hello():
    f = open("/home/pyronia/hello.txt", "r")
    lines = f.readlines()
    print(lines[0])
    f.close()

hello()
