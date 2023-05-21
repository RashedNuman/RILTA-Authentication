"""
                    Rochester Institute of Technology Dubai
                    
                          Authentication CSEC 472.600

                          IoT Authentication Server

Language: Python 3

Group: Rashed Alnuman, Noman Sheikh, Komil Mamasaliev, Syed Izhan

Description: Authentication server (AAA) issues tickets to requested IoT sensors

"""

import rsa
import socket
import ntplib
import string
import random
import secrets
import hashlib
import logging
import threading
from time import ctime
import RSA_ENCRYPTION as RSA

# setting up logging and  using lambda to log
logging.basicConfig(filename = "ServerLogs.log", filemode = 'w', format = '%(message)s', level = logging.ERROR)
logger = lambda msg : logging.error(msg)

# Setting up NTP service
ntp = ntplib.NTPClient()
response = ntp.request('2.pool.ntp.org')
#print(ctime(response.tx_time)) to get the synced time

aliases = dict() # creating ID to alias dictionary

master_key = "12345678909876543212345678909876" # 256 bit secret key

#RSA.generateKeys() # if you need to generate new key pair


with open('clientPU.pem', 'rb') as p:
        clientPU = rsa.PublicKey.load_pkcs1(p.read())

with open('serverPU.pem', 'rb') as p:
        serverPU = rsa.PublicKey.load_pkcs1(p.read())

with open('serverPK.pem', 'rb') as p:
        serverPK = rsa.PrivateKey.load_pkcs1(p.read())

text = "this is a test"


def ServerConnection(connection, address):

    """
    Thread function created by main, connection and address are passed down as parameters,
    then using connection recieves packets from client.
    """
    
    
    with connection:
        
        print(address, "has connected to the server...")

        data = connection.recv(1024)    # recieve bytes data
        str_data = rsa.decrypt(data, serverPK)
        str_data = str_data.decode("utf-8") # translates bytes from socket stream to string


        print(str_data)

        components = str_data.split(' || ')
        user_ID = ''.join(components[0].split('.')) # ID is ip octets combined
        user_public_key = components[1]
        print("ID: ", user_ID)
        print("public key: ", user_public_key)

        ticket = "" 

        with open("aliases.txt", 'r') as file:
            colours = file.read().splitlines()

        while (True):
            
            alias = random.choice(colours)
            
            if alias not in aliases.keys():
                break
            
            else:
                continue

        print("ok done")
        aliases[alias] = user_ID
        print("alias: ", alias)

        # to get the synced time
        current_time = ctime(response.tx_time)
        oldtime = current_time.split()[3].split(':')
        hours = oldtime[0]
        newtime = int(hours) + 2
        newtime = str(newtime) + ':' + oldtime[1] + ':' + oldtime[2]
        lifetime = current_time.replace(current_time.split()[3], newtime)

        print("Lifetime: ", lifetime)

        # now we will create a symmetric key
        
        
        generator = secrets.SystemRandom()
        session_key = ""
        for i in range(31):
            session_key += str(generator.randint(0,9))

        print("session key: ", session_key)

        # creating the ticket
        ticket = lifetime + " || " + alias + " || " + session_key


        # now we create the hash for the ticket
        ticket_hash = hashlib.sha256( ticket.encode()).hexdigest()
        print("hash: ", ticket_hash)

        ticket += " || " + ticket_hash

        ticket_packet = bytes(ticket, encoding = "utf-8")
        connection.send(ticket_packet)

        shareSessionKey("localhost", ticket)
        
        return 0
        
from itertools import cycle         
def enc_XOR(text, key):

    # return key encrypted

    return "".join([chr(ord(c1)^ord(c2)) for (c1,c2) in zip(text,cycle(key))])



def shareSessionKey(ip, ticket):

    port = 7045

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        sock.connect((ip, port))
        print('before encrypt',ticket,'\n')
        ticket = enc_XOR(ticket, master_key)
        print('send to sensor', ticket)

        symmetric_key_packet = bytes(ticket, encoding = "utf-8")
        sock.send(symmetric_key_packet)





def main():

    """
    Main function, static host, port and public key. Creates TCP socket object sock
    and binds to host,port tuple. after listening and connecting to a client, creates
    a connection thread and sends the client connection to that thread and gets ready
    to accept a new client.
    """

    
    host = '127.0.0.1'  # localhost
    port= 5045        # Listening on this specific port



    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        
        sock.bind((host, port))

        while True:
            
            print("Socket bounded succesffuly...")
            print("Awaiting connection...\n")
        
            sock.listen()
        
            connection, address = sock.accept() # when making multi threaded server, we will pass the connection
            msg = connection, " connected"      # and address to the thread function and then wait for another 
                                                # new socket connection from another client
        
       
            socket_thread = threading.Thread(target = ServerConnection, args=(connection, address,))
            msg = "started connection thread for ", connection
            logger(msg)
            socket_thread.start()
            


     
main()
