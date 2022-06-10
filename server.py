import select
import socket
import threading
from threading import Thread
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey, _RSAPrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from encryptor import Encryptor
from fileHandler import FileHandler
from globals import MSG_LENGTH, ACK_MESSAGE, ACK_MESSAGE_FILE, MSG_FILE_LENGTH


class Server:
    gui = None
    serverSocket = None
    serverPort = None
    clientSocket = None
    clientIp = None
    ip = None
    logger = None
    encryptor: Encryptor = None
    privateKey: _RSAPrivateKey = None
    publicKey: _RSAPublicKey = None
    clientPublicKey = None
    sessionKey = None
    fileHandler: FileHandler = None

    def __init__(self, serverIp, SERVER_PORT, logger, encryptor, fileHandler):
        self.ip = serverIp
        self.serverPort = SERVER_PORT
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger
        self.encryptor = encryptor
        self.fileHandler = fileHandler

    def shutDown(self):
        if self.clientSocket is not None:
            self.clientSocket.close()
        if self.serverSocket is not None:
            self.serverSocket.close()
        self.logger.log("Shutting down server " + self.ip)

    def run(self):
        try:
            self.serverSocket.bind((self.ip, self.serverPort))
            self.serverSocket.listen(1)
            self.logger.log("Start listening...")
            # print("SERVER: " + str(threading.current_thread().getName()))
            listenerThread = Thread(target=self.listen, name="Server Listener", daemon=True)
            listenerThread.start()
            return True
        except:
            return False

    def listen(self):
        while True:
            #print("SERVER: " + str(threading.current_thread().getName()))
            serverSocketName = self.serverSocket.getsockname()
            try:
                # print(str(self.serverSocket))
                (self.clientSocket, clientIpPort) = self.serverSocket.accept()
                self.clientIp = clientIpPort[0]
                self.keyExchange()
                self.logger.log("Establieshed connection with client: " + str(self.clientIp))
                receiverThread = threading.Thread(target=self.receiveController, name="Server Receiver", daemon=True)
                receiverThread.start()
            except socket.error:
                self.logger.log("Server Socket: " + str(serverSocketName) + " has been closed")
                break

    def receiveController(self):
        while True:
            # print("SERVER: " + str(threading.current_thread().getName()))
            try:
                (readyToRead, readyToWrite, connectionError) = select.select([self.clientSocket], [], [])
                encryptedMessage = self.clientSocket.recv(MSG_LENGTH)
                message = self.decryptMessage(encryptedMessage).decode()
                if len(message) > 0:
                    if message == "file_begin":
                        self.receiveFile()
                        self.clientSocket.send(ACK_MESSAGE_FILE.encode())
                    else:
                        self.logger.log(message)
                        self.clientSocket.send(ACK_MESSAGE.encode())
                elif len(message) == 0 and len(encryptedMessage) > 0:
                    #self.logger.log("Message decryption failed! Check if you are using a good encryption mode!")
                    self.logger.log(message)
                    self.clientSocket.send(ACK_MESSAGE.encode())
                elif len(message) == 0 and len(encryptedMessage) == 0:
                    self.logger.log("Client " + self.clientIp + " has been disconnected!")
                    break

            except select.error:
                self.logger.log("Client " + self.clientIp + " has been disconnected!")
                self.clientSocket.close()
                break

    def receiveFile(self):
        (readyToRead, readyToWrite, connectionError) = select.select([self.clientSocket], [], [])

        encryptedFileName = self.clientSocket.recv(MSG_LENGTH)
        fileName = self.decryptMessage(encryptedFileName).decode()
        fileName = f"{fileName.rsplit('.', 1)[0]}_decrypted.{fileName.rsplit('.', 1)[-1]}"
        #decryptedMessage = b''
        messages = []
        threadDelegated = False
        while True:
            encryptedMessage = self.clientSocket.recv(MSG_LENGTH)
            message = self.decryptMessage(encryptedMessage)
            #messages.append(message)
            #fileSaver = threading.Thread(target=self.fileHandler.saveToFile, args=(messages, file),
            #                              name="File saver", daemon=True)
            #fileSaver.start()

            #threadDelegated = True
            if message == "file_end".encode():
                break
            self.fileHandler.saveToFile(message, fileName)
            self.clientSocket.send("saved".encode())

        #decryptedMessage += message
        #for i in range(0, len(decryptedMessage), MSG_FILE_LENGTH):
        #length = len(decryptedMessage)




    def decryptMessage(self, encryptedAESMessage):
        print(f'session key: {self.sessionKey}')
        print(f'Encrypted message: {encryptedAESMessage}')
        decryptedAESMessage = self.encryptor.decryptAES(self.sessionKey, encryptedAESMessage)
        print(f'message: {decryptedAESMessage}\n')

        return decryptedAESMessage

    def keyExchange(self):
        self.privateKey, self.publicKey = self.encryptor.readKeysFromFile()
        self.sessionKey = self.encryptor.generateSessionKey()
        # Send public key to client, receive client's public key and send encrypted session key to client
        pemPublicKey = self.publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.clientSocket.send(pemPublicKey)
        pemClientPublicKey = self.clientSocket.recv(MSG_LENGTH)
        self.clientPublicKey = serialization.load_pem_public_key(pemClientPublicKey)

        encryptedSessionKey = self.clientPublicKey.encrypt(
            self.sessionKey,
            padding.OAEP(
                 mgf=padding.MGF1(algorithm=hashes.SHA256()),
                 algorithm=hashes.SHA256(),
                 label=None
            )
        )
        self.clientSocket.send(encryptedSessionKey)

        print(f'Client public key: {self.clientPublicKey}')
        print(f'Session key: {self.sessionKey}')
        print(f'Encrypted session key: {encryptedSessionKey}')
        print(f'Encrypted session key: {encryptedSessionKey}')
