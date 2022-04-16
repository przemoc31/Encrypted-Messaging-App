import socket
CLIENT_PORT = 2023
MSG_LENGTH = 1024


class Client:
    clientSocket = None
    ip = None
    serverIp = None
    logger = None
    encryptor = None

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
            self.logger.log("Establieshed connection with server: " + serverIp)
            return True
        except socket.error as errorMsg:
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