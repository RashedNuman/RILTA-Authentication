import rsa
import socket
import ntplib
from time import ctime
import RSA_ENCRYPTION as RSA



#print(ctime(response.tx_time)) to get the synced time

#RSA.generateKeys() # to generate new key pair

with open('clientPU.pem', 'rb') as p:
        clientPU = rsa.PublicKey.load_pkcs1(p.read())

with open('clientPK.pem', 'rb') as p:
        clientPK = rsa.PrivateKey.load_pkcs1(p.read())

with open('serverPU.pem', 'rb') as p:
        serverPU = rsa.PublicKey.load_pkcs1(p.read())

def enc_XOR(text, key):

    # return key encrypted

    return "".join([chr(ord(c1)^ord(c2)) for (c1,c2) in zip(text,key)])



host = "localhost"  # Server's IP address
port = 5045        # The port the server is specifically listening on

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    
    sock.connect((host, port))
    print("Connected to AAA...\n")

    
    ID = socket.gethostbyname(socket.gethostname()) # our private ip
    ID2 = "localhost" # id of the sensor

    msg1 = ID + ' || ' + ID2
    packet1 = bytes(msg1, encoding = "utf-8")
  
    encrypted_packet = rsa.encrypt(packet1, serverPU)
    sock.send(encrypted_packet)

    ticket = sock.recv(1024)
    ticket = ticket.decode("utf-8")
    session_key = ticket.split(" || ")[-2].strip()
    print()
    
    with open("clientTicket.pem", 'w') as file:
        file.write(ticket)

    #closes
        
    sock.close() # end the connection, not needed but why not


host = "localhost"
port = 7045

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

    sock.connect((host, port))
    print("Connected to sensor")
    print(ticket)
    ticket = enc_XOR(ticket, session_key)
    ticket_packet = bytes(ticket, encoding = "utf-8")
    sock.send(ticket_packet)

    




    
    """
    while True:
        
        inp = input("Enter the msg to the server: ")
        msg = bytes(inp, encoding = "ascii")
        sock.sendto(m sg,(host, port))
        data = sock.recv(1024)

        print('Received from server: ', data.decode("ascii")) # reciebe binary string, decode to ascii
    """
#repr(data)) #prints representable format of the object


"""
from tinyec import registry
import secrets

ecc_curve = registry.get_curve('secp256r1')

private_key = secrets.randbelow(ecc_curve.field.n)
public_key = private_key * ecc_curve.g
print("private key:", private_key)
print("public key:", public_key)

with open("AAA-keypair.txt", 'w') as file:
    file.write(str(private_key))
    file.write("\n\n")
    file.write(str(public_key))
"""
