import hashlib
import os
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"


class Encryptor:
    privateKeyPassword = None
    iv = None

    def __init__(self):
        self.privateKeyPassword = b"JD"

    @staticmethod
    def generateHash(password):
        print('essa')
        result = hashlib.sha3_256(password)
        return result.digest()

    def encryptAES(self, passwordHash, privateKey):
        self.iv = get_random_bytes(AES.block_size)
        cipher = AES.new(passwordHash, AES.MODE_CBC, self.iv)
        return b64encode(cipher.encrypt(pad(privateKey, AES.block_size)))

    def decryptAES(self, passwordHash, privateKey):
        cipher = AES.new(passwordHash, AES.MODE_CBC, self.iv)
        privateKey = b64decode(privateKey)
        return unpad(cipher.decrypt(privateKey), AES.block_size)

    @staticmethod
    def saveKeysToFile(encryptedPrivateKey, publicKey):
        with open(PRIVATE_KEY_PATH, "w") as privateFile:
            privateFile.write(encryptedPrivateKey.decode())

        with open(PUBLIC_KEY_PATH, "w") as publicFile:
            publicFile.write(publicKey.decode())

    def generateKeys(self):
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        formattedPrivateKey = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        '''key = RSA.generate(4096)
        private_key = key.export_key('PEM')
        public_key = key.publickey().exportKey('PEM')
        message = 'essa bangla i te de'
        message = str.encode(message)

        rsa_public_key = RSA.importKey(public_key)
        rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
        encrypted_text = rsa_public_key.encrypt(message)

        print(encrypted_text)

        rsa_private_key = RSA.importKey(private_key)
        rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
        decrypted_text = rsa_private_key.decrypt(encrypted_text)

        print(decrypted_text)'''

        passwordHash = self.generateHash(self.privateKeyPassword)
        encryptedPrivateKey = self.encryptAES(passwordHash, formattedPrivateKey)

        publicKey = privateKey.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # print(formattedPrivateKey)
        # print(self.decryptAES(passwordHash, self.encryptAES(passwordHash, formattedPrivateKey)))

        self.saveKeysToFile(encryptedPrivateKey, publicKey)

    @staticmethod
    def destroyKeys():
        try:
            os.remove(PRIVATE_KEY_PATH)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

        try:
            os.remove(PUBLIC_KEY_PATH)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))
