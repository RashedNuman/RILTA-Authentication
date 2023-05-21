"""
import ntplib
from time import ctime

ntp = ntplib.NTPClient()
response = ntp.request('pool.ntp.org')
x = ctime(response.tx_time)# to get the synced time
print(x)
oldtime = x.split()[3].split(':')
hours = oldtime[0]
newtime = int(hours) + 2
newtime = str(newtime) + ':' + oldtime[1] + ':' + oldtime[2]
print(newtime)
"""


import socket
import threading

master_key = "12345678909876543212345678909876" # 256 bit secret key
from itertools import cycle  
def enc_XOR(text, key):

    # return key encrypted

    return "".join([chr(ord(c1)^ord(c2)) for (c1,c2) in zip(text,cycle(key))])


host = '127.0.0.1'  # localhost
port= 7045        
sharekey = ''
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        sock.bind((host, port))

        while True:
            try:
                print("Socket bounded successfuly...")
                print("Awaiting connection...\n")
            
                sock.listen()
            
                connection, address = sock.accept() # when making multi threaded server, we will pass the connection
                msg = connection, " connected"      # and address to the thread function and then wait for another 
                                                    # new socket connection from another client

                ticket = connection.recv(1024)
                ticket = ticket.decode("utf-8")
                print(ticket)
                decrypted_ticket = enc_XOR(ticket, master_key)
                session_key = decrypted_ticket.split(" || ")[-2].strip()
                print(session_key)

                sharekey = session_key
            except Exception:
                decrypted_ticket = enc_XOR(ticket, sharekey)
                session_key = decrypted_ticket.split(" || ")[-2].strip()
                print('\tFinished This is the session: ',decrypted_ticket)
                print('\tsession key: ',session_key)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

    sock.bind((host, port))

    sock.listen()
    connection, address = sock.accept()
    user_ticket = connection.recv(1024)
    decrypted_ticket = enc_XOR(user_ticket, sesion_key)
    print("\nRecieved Authentication Ticket From User...\n")
    print(decrypted_ticket)
        
            
          
