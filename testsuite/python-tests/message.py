class Message:
    greeting = ""
    name = ""

    def __init__(self, gr):
        self.greeting = gr

    def set_name(self, n):
        self.name = n

    def print_msg(self):
        print(self.greeting+", "+self.name)
