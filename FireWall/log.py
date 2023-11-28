import os
import time
import socket
import struct

last_time = 0.0

while True:
    os.system("dmesg > ./temp")
    log = open("./log","a")
    temp = open("./temp","r")
    temp_lines = temp.readlines()
    
    for line in temp_lines:
        index = line.find(']')
        now_time = float(line[1:index])
        if last_time < now_time and line[index+2:index+12]=="myfirewall":
            list = line[index+14:].split()
            log.write(list[0]+' ')
            data = time.localtime(int(list[1]))
            data = time.strftime("%Y-%m-%d %H:%M:%S",data)
            log.write(data+' ')
            log.write(list[2]+' ')
            if list[2] == 'TCP' or list[2] == 'UDP':
                log.write(socket.inet_ntoa(struct.pack("I", int(list[3])))+' ')
                log.write(str(socket.ntohs(int(list[4])))+' ')
                log.write(socket.inet_ntoa(struct.pack("I", int(list[5])))+' ')
                log.write(str(socket.ntohs(int(list[6])))+' ')
            elif list[2] == 'ICMP':
                log.write(socket.inet_ntoa(struct.pack("I", int(list[3])))+' ')
                log.write(socket.inet_ntoa(struct.pack("I", int(list[4])))+' ')
            log.write(list[-1]+'\n')
    
    index = temp_lines[-1].find(']')
    last_time = float(temp_lines[-1][1:index])
    log.close()
    temp.close()
    time.sleep(5)

# print(socket.ntohs(22435))