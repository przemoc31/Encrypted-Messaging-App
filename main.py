import socket
import sys
import threading
from threading import Thread
import time
import tkinter
import customtkinter
import select

HOST_IP = '192.168.42.37'
RECIPIENT_IP = '192.168.42.37'
SERVER_PORT = 2022
CLIENT_PORT = 2023
MSG_LENGTH = 1024
ENCODING = "utf-8"


class Server:
    gui = None
    serverSocket = None
    clientSocket = None
    clientIp = None
    ip = None
    logger = None

    def __init__(self, serverIp, logger):
        self.ip = serverIp
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger

    def __del__(self):
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
            try:
                #print(str(self.serverSocket))
                serverSocketName = self.serverSocket.getsockname()
                (self.clientSocket, clientIpPort) = self.serverSocket.accept()
                self.clientIp = clientIpPort[0]
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
                    self.logger.log("Received Message: " + message)
                elif len(message) == 0:
                    self.logger.log("Client " + self.clientIp + " has been disconnected!")
                    break

            except select.error:
                self.logger.log("Client " + self.clientIp + " has been disconnected!")
                self.clientSocket.close()
                break


class Client:
    clientSocket = None
    ip = None
    serverIp = None
    logger = None

    def __init__(self, clientIp, logger):
        self.ip = clientIp
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.logger = logger

    def __del__(self):
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
        except socket.error:
            if self.serverIp is not None:
                self.logger.log("Server " + self.serverIp + " has been disconnected!")
            else:
                self.logger.log("You are not allowed to send a message. Connect to the server!")

    def detectMessage(self, message):
        if message is not None:
            self.sendMessage(message)


class GUI(customtkinter.CTk):
    WIDTH = 950
    HEIGHT = 600
    message = None
    __server: Server = None
    __client: Client = None

    def __init__(self):
        super(GUI, self).__init__()

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
        return self.__server

    def getClient(self):
        return self.__client

    def setServer(self, server):
        self.__server = server

    def setClient(self, client):
        self.__client = client

    def serverButtonEvent(self):
        if self.serverButton.fg_color != self.serverButton.hover_color:
            # TURN ON SERVER
            self.serverButton.config(fg_color=self.serverButton.hover_color)
            succeed = setUpServer(self)
            if succeed is False:
                # ERROR IN CONNECTING
                self.serverButton.config(fg_color=self.sendButton.fg_color)
        elif self.serverButton.fg_color == self.serverButton.hover_color:
            # TURN OFF SERVER
            self.serverButton.config(fg_color=self.sendButton.fg_color)
            self.__server.__del__()

    def clientButtonEvent(self):
        if self.clientButton.fg_color != self.clientButton.hover_color:
            # TURN ON CLIENT
            self.clientButton.config(fg_color=self.clientButton.hover_color)
            succeed = setUpClient(self)
            if succeed is False:
                # ERROR IN CONNECTING
                self.clientButton.config(fg_color=self.sendButton.fg_color)
        elif self.clientButton.fg_color == self.clientButton.hover_color:
            # TURN OFF CLIENT
            self.clientButton.config(fg_color=self.sendButton.fg_color)
            self.__client.__del__()

    def key_press(self, event):
        self.handleSending()

    def handleSending(self):
        message = self.messageInput.get()
        self.messageInput.delete(0, "end")
        self.messageInput.clear_placeholder()
        try:
            self.__client.detectMessage(message)
        except AttributeError:
            self.messageBox.config(text=self.messageBox.cget("text") + "You are not allowed to send a message. Connect to the server!" + "\n")

    def switchMode(self):
        if self.modeSwitch.get() == 1:
            customtkinter.set_appearance_mode("light")
        else:
            customtkinter.set_appearance_mode("dark")

    def run(self):
        print("GUI: " + str(threading.current_thread().getName()))
        self.mainloop()

    def shutDown(self):
        if self.__client is not None:
            if self.__client.clientSocket is not None:
                self.__client.clientSocket.close()
        if self.__server is not None:
            if self.__server.clientSocket is not None:
                self.__server.clientSocket.close()
            if self.__server.serverSocket is not None:
                self.__server.serverSocket.close()
        sys.exit(0)


class Logger:
    gui = None

    def __init__(self, gui):
        self.gui = gui

    def log(self, text):
        self.gui.messageBox.config(text=self.gui.messageBox.cget("text") + text + "\n")


def setUpServer(gui):
    logger = Logger(gui)
    server = Server(HOST_IP, logger)
    gui.setServer(server)
    succeed = server.run()
    if succeed is True:
        return True
    else:
        return False


def setUpClient(gui):
    logger = Logger(gui)
    client = Client(HOST_IP, logger)
    gui.setClient(client)
    succeed = client.connect(RECIPIENT_IP)
    if succeed is True:
        return True
    else:
        return False


def main():
    gui = GUI()
    gui.run()


if __name__ == '__main__':
    main()
