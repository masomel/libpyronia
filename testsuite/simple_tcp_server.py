import socket
import sys
import signal

HOST = '127.0.0.1'
PORT = 8000

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))

print('Listening...')
s.listen(1)

try:
    while True:       
        conn, addr = s.accept()
        print('Connection from '+addr[0]+':'+str(addr[1]))
        conn.send("hello!")
        conn.close()
except KeyboardInterrupt:
    print 'Goodbye!'
    s.close()
    sys.exit(0)
    
