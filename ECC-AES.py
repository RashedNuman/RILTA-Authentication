
"""
key = ECC.generate(curve = "P-256") # private
public = key.public_key()  # public key


with open("mykey.pem", 'wt') as file:
    file.write(key.export_key(format='PEM'))

with open("mykey2.pem", 'wt') as file:
    file.write(public.export_key(format='PEM'))


with open("mykey2.pem", 'rb') as key_file:
    publicKey = ECC.import_key(key_file.read())
    #privateKey = rsa.PrivateKey.load_pkcs1(key_file.read())

print(publicKey)

text = "hello world"
ciphertext = rsa.encrypt(text.encode('ascii'), publicKey)
print(ciphertext)
plaintext = rsa.decrypt(ciphertext, privateKey).decode("ascii")
print(plaintext)
"""


from tinyec import registry
from Crypto.Cipher import AES
import hashlib, secrets, binascii
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encrypt_ECC(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    ciphertext, nonce, authTag = encrypt_AES_GCM(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def decrypt_ECC(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_point_to_256_bit_key(sharedECCKey)
    plaintext = decrypt_AES_GCM(ciphertext, nonce, authTag, secretKey)
    return plaintext

msg = b'this is not a test'

print("original msg: ", msg)

#curve = registry.get_curve('brainpoolP256r1')
curve = registry.get_curve('NIST P-256')
privKey = secrets.randbelow(curve.field.n)
pubKey = privKey * curve.g

x = encrypt_ECC(msg, pubKey)
y = decrypt_ECC(x, privKey)
print(y)

encryptedMsg = encrypt_ECC(msg, pubKey)

"""
encryptedMsgObj = {
    'ciphertext': binascii.hexlify(encryptedMsg[0]),
    'nonce': binascii.hexlify(encryptedMsg[1]),
    'authTag': binascii.hexlify(encryptedMsg[2]),
    'ciphertextPubKey': hex(encryptedMsg[3].x) + hex(encryptedMsg[3].y % 2)[2:]
}
print("encrypted msg: ", encryptedMsgObj)
"""
decryptedMsg = decrypt_ECC(encryptedMsg, privKey)
print("decrypted msg: ", decryptedMsg)

