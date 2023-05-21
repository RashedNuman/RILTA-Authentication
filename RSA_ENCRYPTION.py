import rsa

"""
(publicKey, privateKey) = rsa.newkeys(1024)
print(publicKey)

with open("publicKey.pem", "wb") as file:
    file.write(publicKey.save_pkcs1("PEM"))

with open("privateKey.pem", "wb") as file:
    file.write(privateKey.save_pkcs1("PEM"))

"""

def generate_ECC_keys():

    ecc_curve = registry.get_curve('secp256r1')
    private_key = secrets.randbelow(ecc_curve.field.n)
    public_key = private_key * ecc_curve.g
    
def generateKeys():
    (publicKey, privateKey) = rsa.newkeys(1024)
    with open('publcKey.pem', 'wb') as p:
        p.write(publicKey.save_pkcs1('PEM'))

    with open('privateKey.pem', 'wb') as p:
        p.write(privateKey.save_pkcs1('PEM'))

def loadKeys():
    with open('publicKey.pem', 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    with open('privateKey.pem', 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    return privateKey, publicKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):

    return rsa.decrypt(ciphertext, key).decode('ascii')
  
      
def sign(message, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-256')


def verify(message, signature, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key,) == 'SHA-256'
    except:
        return False


"""
private, public = loadKeys()

msg = "hello world"

ciphertext = encrypt(msg, public)

signature = sign(msg, private)

text = decrypt(ciphertext, private)

signcheck = verify(text, signature, public)
"""


