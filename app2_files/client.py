import socket
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives import serialization
from globals import CLIENT_PORT, MSG_LENGTH


class Client:
    clientSocket = None
    ip = None
    serverIp = None
    logger = None
    encryptor = None
    privateKey: _RSAPublicKey = None
    publicKey: _RSAPublicKey = None
    serverPublicKey = None
    sessionKey = None

    def __init__(self, clientIp, logger, encryptor):
        self.ip = clientIp
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger
        self.encryptor = encryptor

    def shutDown(self):
        if self.clientSocket is not None:
            self.clientSocket.close()
        self.logger.log("Shutting down client " + self.ip)

    def connect(self, serverIp):
        try:
            self.clientSocket.connect((serverIp, CLIENT_PORT))
            self.serverIp = serverIp
            self.keyExchange()
            self.logger.log("Establieshed connection with server: " + serverIp)
            return True
        except socket.error:
            self.logger.log("Couldn't connect to server: " + serverIp)
            return False

    def sendMessage(self, message):
        # print(message)
        try:
            self.clientSocket.send(message.encode())
            ackMessage = self.clientSocket.recv(MSG_LENGTH).decode()
            self.logger.log(ackMessage)
        except socket.error:
            if self.serverIp is not None:
                self.logger.log("Server " + self.serverIp + " has been disconnected!")
            else:
                self.logger.log("You are not allowed to send a message. Connect to the server!")

    def detectMessage(self, message):
        if message is not None:
            self.sendMessage(message)

    def keyExchange(self):
        # Send public key to server and receive server's public key and encrypted session key
        self.privateKey, self.publicKey = self.encryptor.readKeysFromFile()
        pemPublicKey = self.publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.clientSocket.send(pemPublicKey)
        pemServerPublicKey = self.clientSocket.recv(MSG_LENGTH)
        self.serverPublicKey = serialization.load_pem_public_key(pemServerPublicKey)
        self.sessionKey = self.clientSocket.recv(MSG_LENGTH)
        print(f'Server public key: {self.serverPublicKey}')
        print(f'Session key: {self.sessionKey}')
