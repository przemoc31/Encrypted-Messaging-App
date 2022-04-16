import socket
import sys
import threading
from threading import Thread
import tkinter

import secrets
import customtkinter
import select

from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
import hashlib
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST_IP = '192.168.0.158'
RECIPIENT_IP = '192.168.0.158'
SERVER_PORT = 2023
CLIENT_PORT = 2022
MSG_LENGTH = 1024
ENCODING = "utf-8"
ACK_MESSAGE = f"Server {HOST_IP} received a message"
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"
SESSION_KEY_LENGTH = 32


class Encryptor:
    privateKeyPassword = None
    privateKeyPasswordHash = None
    iv = None

    def __init__(self):
        self.privateKeyPassword = b"JD"

    def generateHash(self, password):
        result = hashlib.sha3_256(password)
        print(result.digest())
        return result.digest()

    def encryptAES(self, passwordHash, privateKey):
        self.iv = get_random_bytes(AES.block_size)
        cipher = AES.new(passwordHash, AES.MODE_CBC, self.iv)
        return b64encode(cipher.encrypt(pad(privateKey, AES.block_size)))

    def decryptAES(self, passwordHash, privateKey):
        cipher = AES.new(passwordHash, AES.MODE_CBC, self.iv)
        privateKey = b64decode(privateKey)
        return unpad(cipher.decrypt(privateKey), AES.block_size)

    def saveKeysToFile(self, encryptedPrivateKey, publicKey):
        with open(PRIVATE_KEY_PATH, "w") as privateFile:
            privateFile.write(encryptedPrivateKey.decode())

        with open(PUBLIC_KEY_PATH, "w") as publicFile:
            publicFile.write(publicKey.decode())

    def readKeysFromFile(self):
        with open(PRIVATE_KEY_PATH, "rb") as key_file:
            privateKey = serialization.load_pem_private_key(
                self.decryptAES(self.privateKeyPasswordHash, key_file.read()),
                password=None
            )

        with open(PUBLIC_KEY_PATH, "rb") as publicFile:
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

        # print(formattedPrivateKey)
        # print(self.decryptAES(privateKeyPasswordHash, self.encryptAES(privateKeyPasswordHash, formattedPrivateKey)))

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
            os.remove(PRIVATE_KEY_PATH)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

        try:
            os.remove(PUBLIC_KEY_PATH)
        except OSError as e:
            print("Error: %s - %s." % (e.filename, e.strerror))

    def generateSessionKey(self):
        session_key = secrets.token_bytes(SESSION_KEY_LENGTH)
        return session_key


class Server:
    gui = None
    serverSocket = None
    clientSocket = None
    clientIp = None
    ip = None
    logger = None
    encryptor = None
    privateKey: _RSAPublicKey = None
    publicKey: _RSAPublicKey = None
    clientPublicKey = None
    sessionKey = None

    def __init__(self, serverIp, logger, encryptor):
        self.ip = serverIp
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger
        self.encryptor = encryptor

    def shutDown(self):
        if self.clientSocket is not None:
            self.clientSocket.close()
        if self.serverSocket is not None:
            self.serverSocket.close()
        self.logger.log("Shutting down server " + self.ip)

    def run(self):
        try:
            self.serverSocket.bind((self.ip, SERVER_PORT))
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
            print("SERVER: " + str(threading.current_thread().getName()))
            serverSocketName = self.serverSocket.getsockname()
            try:
                # print(str(self.serverSocket))
                (self.clientSocket, clientIpPort) = self.serverSocket.accept()
                self.clientIp = clientIpPort[0]
                self.keyExchange()
                self.logger.log("Establieshed connection with client: " + str(self.clientIp))
                receiverThread = threading.Thread(target=self.receiveMessage, name="Server Receiver", daemon=True)
                receiverThread.start()
            except socket.error:
                self.logger.log("Server Socket: " + str(serverSocketName) + " has been closed")
                break

    def receiveMessage(self):
        while True:
            # print("SERVER: " + str(threading.current_thread().getName()))
            try:
                (readyToRead, readyToWrite, connectionError) = select.select([self.clientSocket], [], [])
                message = self.clientSocket.recv(MSG_LENGTH).decode()
                if len(message) > 0:
                    self.logger.log(message)
                    self.clientSocket.send(ACK_MESSAGE.encode())
                elif len(message) == 0:
                    self.logger.log("Client " + self.clientIp + " has been disconnected!")
                    break

            except select.error:
                self.logger.log("Client " + self.clientIp + " has been disconnected!")
                self.clientSocket.close()
                break

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
        self.clientSocket.send(self.sessionKey)
        print(f'Client public key: {self.clientPublicKey}')
        print(f'Session key: {self.sessionKey}')


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


class GUI(customtkinter.CTk):
    WIDTH = 950
    HEIGHT = 600
    message = None
    encryptor = None
    server: Server = None
    client: Client = None

    def __init__(self, encryptor):
        super(GUI, self).__init__()
        self.encryptor = encryptor

        # GUI SETTINGS
        customtkinter.set_appearance_mode("System")
        customtkinter.set_default_color_theme("blue")
        self.title("BSK Messaging App")
        self.geometry(f"{self.WIDTH}x{self.HEIGHT}")
        customtkinter.set_appearance_mode("dark")

        # EXIT PROTOCOL
        self.protocol("WM_DELETE_WINDOW", self.shutDown)
        self.bind("<Escape>", self.shutDown)
        self.bind('<Return>', self.key_press)

        # FRAME
        self.grid_columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

        # LEFT FRAME WIDTH 150
        self.frame_left = customtkinter.CTkFrame(master=self, width=150, corner_radius=0)
        self.frame_left.grid(row=0, column=0, sticky="nswe")

        # RIGHT FRAME WIDTH 800
        self.frame_right = customtkinter.CTkFrame(master=self)
        # WIDTH 750
        self.frame_right.grid(row=0, column=1, sticky="nswe", padx=25, pady=25)

        # SERVER BUTTON
        self.serverButton = customtkinter.CTkButton(master=self.frame_left, text="SERVER",
                                                    fg_color=("gray75", "gray30"), command=self.serverButtonEvent)
        self.serverButton.grid(pady=10, padx=20)

        # CLIENT BUTTON
        self.clientButton = customtkinter.CTkButton(master=self.frame_left, text="CLIENT",
                                                    fg_color=("gray75", "gray30"), command=self.clientButtonEvent)
        self.clientButton.grid(pady=10, padx=20)

        # LIGHT MODE SWITCH
        self.modeSwitch = customtkinter.CTkSwitch(master=self.frame_left, text="Light Mode", command=self.switchMode)
        self.modeSwitch.grid(pady=10, padx=20, sticky="w")

        # MESSAGE BOX
        self.messageBox = tkinter.Label(master=self.frame_right, font=("Helvetica", 12), fg='#fff',
                                        bg=self.frame_left.fg_color[1])
        # WIDTH 700
        self.messageBox.grid(padx=25, pady=25)

        # MESSAGE INPUT
        self.messageInput = customtkinter.CTkEntry(master=self.frame_right, width=550,
                                                   placeholder_text="Send a message")
        self.messageInput.place(y=500, x=20)

        # CLIENT BUTTON
        self.sendButton = customtkinter.CTkButton(master=self.frame_right, text="SEND", fg_color=("gray75", "gray30"),
                                                  command=self.handleSending)
        self.sendButton.place(y=500, x=600)

    def getServer(self):
        return self.server

    def getClient(self):
        return self.client

    def setServer(self, server):
        self.server = server

    def setClient(self, client):
        self.client = client

    def serverButtonEvent(self):
        if self.serverButton.fg_color != self.serverButton.hover_color:
            # TURN ON SERVER
            self.serverButton.config(fg_color=self.serverButton.hover_color)
            succeed = self.setUpServer()
            if succeed is False:
                # ERROR IN CONNECTING
                self.serverButton.config(fg_color=self.sendButton.fg_color)
        else:
            # TURN OFF SERVER
            self.serverButton.config(fg_color=self.sendButton.fg_color)
            self.server.shutDown()

    def clientButtonEvent(self):
        if self.clientButton.fg_color != self.clientButton.hover_color:
            # TURN ON CLIENT
            self.clientButton.config(fg_color=self.clientButton.hover_color)
            succeed = self.setUpClient()
            if succeed is False:
                # ERROR IN CONNECTING
                self.clientButton.config(fg_color=self.sendButton.fg_color)
        else:
            # TURN OFF CLIENT
            self.clientButton.config(fg_color=self.sendButton.fg_color)
            self.client.shutDown()

    def key_press(self, event):
        self.handleSending()

    def handleSending(self):
        message = self.messageInput.get()
        self.messageInput.delete(0, "end")
        self.messageInput.clear_placeholder()
        try:
            self.client.detectMessage(message)
        except AttributeError:
            self.messageBox.config(
                text=f'{self.messageBox.cget("text")} You are not allowed to send a message. Connect to the server!\n')

    def switchMode(self):
        if self.modeSwitch.get() == 1:
            customtkinter.set_appearance_mode("light")
        else:
            customtkinter.set_appearance_mode("dark")

    def setUpServer(self):
        logger = Logger(self)
        self.server = Server(HOST_IP, logger, self.encryptor)
        succeed = self.server.run()
        if succeed is True:
            return True
        else:
            return False

    def setUpClient(self):
        logger = Logger(self)
        self.client = Client(HOST_IP, logger, self.encryptor)
        succeed = self.client.connect(RECIPIENT_IP)
        if succeed is True:
            return True
        else:
            return False

    def run(self):
        print("GUI: " + str(threading.current_thread().getName()))
        self.mainloop()

    def shutDown(self):
        if self.client is not None:
            self.client.shutDown()
        if self.server is not None:
            self.server.shutDown()
        self.encryptor.destroyKeys()
        sys.exit(0)


class Logger:
    gui = None

    def __init__(self, gui):
        self.gui = gui

    def log(self, text):
        self.gui.messageBox.config(text=self.gui.messageBox.cget("text") + text + "\n")


def main():
    encryptor = Encryptor()
    encryptor.generateKeys()
    gui = GUI(encryptor)
    gui.run()


if __name__ == '__main__':
    main()
