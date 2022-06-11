import math
import socket
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode

from fileHandler import FileHandler
from globals import MSG_LENGTH, MSG_FILE_LENGTH
from encryptor import Encryptor
import time


class Client:
    clientSocket = None
    clientPort = None
    ip = None
    serverIp = None
    logger = None
    encryptor: Encryptor = None
    privateKey: _RSAPrivateKey = None
    publicKey: _RSAPublicKey = None
    serverPublicKey = None
    sessionKey = None
    fileHandler: FileHandler = None

    def __init__(self, clientIp, CLIENT_PORT, logger, encryptor, fileHandler):
        self.ip = clientIp
        self.clientPort = CLIENT_PORT
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger
        self.encryptor = encryptor
        self.fileHandler = fileHandler

    def shutDown(self):
        if self.clientSocket is not None:
            self.clientSocket.close()
        self.logger.log("Shutting down client " + self.ip)

    def connect(self, serverIp):
        try:
            self.clientSocket.connect((serverIp, self.clientPort))
            self.serverIp = serverIp
            self.keyExchange()
            self.logger.log("Establieshed connection with server: " + serverIp)
            return True
        except socket.error:
            self.logger.log("Couldn't connect to server: " + serverIp)
            return False

    def openFile(self, file, progressBar):
        self.fileHandler.readFromFile(file)
        self.sendFile(self.fileHandler.content, progressBar)

    def sendFile(self, file, progressBar):
        try:
            self.clientSocket.send("file_begin".encode())
            self.clientSocket.send(self.encryptMessage(self.fileHandler.fileName.encode()))
            bytesInFile = len(self.fileHandler.content)
            for i in range(0, bytesInFile, MSG_FILE_LENGTH):
                testMessage = self.fileHandler.content[i:i + MSG_FILE_LENGTH]
                self.clientSocket.send(self.encryptMessage(testMessage))
                nextBytes = self.clientSocket.recv(4)
                time.sleep(0.01)
                value = (i / bytesInFile) * 100
                self.updateProgressBar(progressBar, value)

            self.updateProgressBar(progressBar, 100)
            self.clientSocket.send(self.encryptMessage("file_end".encode()))
            time.sleep(0.01)

            ackMessage = self.clientSocket.recv(MSG_LENGTH).decode()
            if ackMessage is not None:
                self.logger.log(ackMessage)

        except socket.error:
            if self.serverIp is not None:
                self.logger.log("Server " + self.serverIp + " has been disconnected!")
            else:
                self.logger.log("You are not allowed to send a message. Connect to the server!")

        return None

    def updateProgressBar(self, progressBar, value):
        progressBar['value'] = value

    def sendMessage(self, message):
        # print(message)
        try:
            self.clientSocket.send(self.encryptMessage(message.encode()))
            self.clientSocket.settimeout(1.0)
            ackMessage = self.clientSocket.recv(MSG_LENGTH).decode()
            if ackMessage is not None:
                self.logger.log(ackMessage)
        except socket.error:
            if self.serverIp is not None:
                self.logger.log("Server " + self.serverIp + " has been disconnected!")
            else:
                self.logger.log("You are not allowed to send a message. Connect to the server!")

    def detectMessage(self, message):
        if message is not None:
            self.sendMessage(message)

    def encryptMessage(self, message):
        #print(f'session key: {self.sessionKey}')
        encryptedAESMessage = self.encryptor.encryptAES(self.sessionKey, message)
        #print(f'message: {message}')
        #print(f'Encrypted message: {encryptedAESMessage}\n')
        return encryptedAESMessage

    def encryptMessageWithKey(self, message, key):
        #print(f'session key: {self.sessionKey}')
        encryptedAESMessage = self.encryptor.encryptAES(key, message)
        #print(f'message: {message}')
        #print(f'Encrypted message: {encryptedAESMessage}\n')
        return encryptedAESMessage

    def keyExchange(self):
        # Send public key to server and receive server's public key and encrypted session key
        self.privateKey, self.publicKey = self.encryptor.readKeysFromFile()
        pemPublicKey = self.publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        try:
            self.clientSocket.send(pemPublicKey)
            pemServerPublicKey = self.clientSocket.recv(MSG_LENGTH)
            self.serverPublicKey = serialization.load_pem_public_key(pemServerPublicKey)
            encryptedSessionKey = self.clientSocket.recv(MSG_LENGTH)
            self.sessionKey = self.privateKey.decrypt(
                encryptedSessionKey,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                ))
        except socket.error:
            if self.serverIp is not None:
                self.logger.log("Server " + self.serverIp + " has been disconnected!")
            else:
                self.logger.log("You are not allowed to exchange the public keys. Connect to the server!")

        #print(f'Server public key: {self.serverPublicKey}')
        # print(f'Encrypted Session key: {encryptedSessionKey}')
        #print(f'Decrypted Session key: {self.sessionKey}')
