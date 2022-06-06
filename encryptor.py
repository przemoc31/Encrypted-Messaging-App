import hashlib
import os
import secrets
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from globals import SESSION_KEY_LENGTH


class Encryptor:
    privateKeyPassword = None
    privateKeyPasswordHash = None
    iv = None
    AES_MODE = None
    pathToPrivate = None
    pathToPublic = None

    def __init__(self, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH):
        self.privateKeyPassword = b"JD"
        self.AES_MODE = AES.MODE_CBC
        self.pathToPrivate = PRIVATE_KEY_PATH
        self.pathToPublic = PUBLIC_KEY_PATH

    def switchEncryptionMode(self, AES_MODE):
        if AES_MODE == "CBC":
            self.AES_MODE = AES.MODE_CBC
        elif AES_MODE == "ECB":
            self.AES_MODE = AES.MODE_ECB
        elif AES_MODE == "CFB":
            self.AES_MODE = AES.MODE_CFB
        elif AES_MODE == "OFB":
            self.AES_MODE = AES.MODE_OFB

    def generateHash(self, password):
        result = hashlib.sha3_256(password)
        return result.digest()

    def encryptAES(self, key, data):
        #self.iv = get_random_bytes(AES.block_size)
        if self.AES_MODE != AES.MODE_ECB:
            self.iv = bytes([0xa3, 0x11, 0xaa, 0xc0, 0x0d, 0xee, 0xf1, 0xff,
                             0x01, 0x03, 0x07, 0x00, 0x25, 0x58, 0x99, 0xc3])
            cipher = AES.new(key, self.AES_MODE, self.iv)
            return b64encode(cipher.encrypt(pad(data, AES.block_size)))
        else:
            cipher = AES.new(key, self.AES_MODE)
            return b64encode(cipher.encrypt(pad(data, AES.block_size)))

    def decryptAES(self, key, data):
        try:
            if self.AES_MODE != AES.MODE_ECB:
                cipher = AES.new(key, self.AES_MODE, self.iv)
            else:
                cipher = AES.new(key, self.AES_MODE)
            data = b64decode(data)

            result = unpad(cipher.decrypt(data), AES.block_size)
        except ValueError:
            result = b64encode(self.generateSessionKey())

        return result

    def saveKeysToFile(self, encryptedPrivateKey, publicKey):
        with open(self.pathToPrivate, "w") as privateFile:
            privateFile.write(encryptedPrivateKey.decode())

        with open(self.pathToPublic, "w") as publicFile:
            publicFile.write(publicKey.decode())

    def readKeysFromFile(self):
        with open(self.pathToPrivate, "rb") as key_file:
            privateKey = serialization.load_pem_private_key(
                self.decryptAES(self.privateKeyPasswordHash, key_file.read()),
                password=None
            )

        with open(self.pathToPublic, "rb") as publicFile:
            publicKey = serialization.load_pem_public_key(publicFile.read())

        return privateKey, publicKey

    def generateKeys(self):
        privateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096
        )

        pemPrivateKey = privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        self.privateKeyPasswordHash = self.generateHash(self.privateKeyPassword)
        encryptedPemPrivateKey = self.encryptAES(self.privateKeyPasswordHash, pemPrivateKey)

        publicKey = privateKey.public_key()

        pemPublicKey = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        #print(self.decryptAES(self.privateKeyPasswordHash, self.encryptAES(self.privateKeyPasswordHash, pemPrivateKey)))

        self.saveKeysToFile(encryptedPemPrivateKey, pemPublicKey)

        '''with open(PRIVATE_KEY_PATH, "rb") as key_file:
            privateKey2 = serialization.load_pem_private_key(
            self.decryptAES(privateKeyPasswordHash, key_file.read()),
            password=None
            )

        msg = publicKey.encrypt("JD DISA".encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        original_message = privateKey2.decrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        print(original_message.decode())'''

    def destroyKeys(self):
        try:
            os.remove(self.pathToPrivate)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

        try:
            os.remove(self.pathToPublic)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

    def generateSessionKey(self):
        sessionKey = secrets.token_bytes(SESSION_KEY_LENGTH)
        return sessionKey
