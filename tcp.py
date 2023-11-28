import os
import sys
import socket
import time

client_ip = "192.168.192.129"
client_port = 12346
server_ip = "192.168.147.1"
server_port = 12346

def server_tcp():
    # tcp
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = server_ip
    port = server_port
    s.bind((host, port))
    s.listen(5)
    while True:
        c, addr = s.accept()
        print ('Got connection from', addr)
        print (c.recv(1024))
        c.close()

def server_udp():
    # udp
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    host = server_ip
    port = server_port
    s.bind((host, port))
    while True:
        data, addr = s.recvfrom(1024)
        print ("received message:", data)
        print ("from:", addr)

def http_server():
    # http server
    os.system("python3 -m http.server 8000")
    
if __name__ == '__main__':
    args = sys.argv
    if len(args) < 3:
        print ("Usage: python test.py [client|server] [tcp|udp]")
        sys.exit()
    if args[1] == "client":
        if args[2] == "tcp":
            client_tcp()
        elif args[2] == "udp":
            client_udp()
        else:
            print ("Usage: python test.py [client|server] [tcp|udp]")
            sys.exit()
    elif args[1] == "server":
        if args[2] == "tcp":
            server_tcp()
        elif args[2] == "udp":
            server_udp()
        else:
            print ("Usage: python test.py [client|server] [tcp|udp]")
            sys.exit()
    elif args[1] == "http":
        if args[2] == "server":
            http_server()
    else:
        print ("Usage: python test.py [client|server] [tcp|udp]")
        sys.exit()

