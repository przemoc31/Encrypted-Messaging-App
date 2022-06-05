import sys
import tkinter
import customtkinter
from logger import Logger
from server import Server
from client import Client
from fileHandler import FileHandler


class GUI(customtkinter.CTk):
    WIDTH = 950
    HEIGHT = 600
    message = None
    encryptor = None
    server: Server = None
    client: Client = None
    fileHandler: FileHandler = None
    encryptionButton: customtkinter.CTkButton = None
    encryptionButtons = []

    def __init__(self, encryptor, HOST_IP, RECIPIENT_IP, SERVER_PORT, CLIENT_PORT):
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
                                                    fg_color=("gray75", "gray30"),
                                                    command=lambda: self.serverButtonEvent(HOST_IP, SERVER_PORT))
        self.serverButton.grid(pady=10, padx=20)

        # CLIENT BUTTON
        self.clientButton = customtkinter.CTkButton(master=self.frame_left, text="CLIENT",
                                                    fg_color=("gray75", "gray30"),
                                                    command=lambda: self.clientButtonEvent(HOST_IP, RECIPIENT_IP,
                                                                                           CLIENT_PORT))
        self.clientButton.grid(pady=10, padx=20)

        # CBC BUTTON
        self.CBCButton = customtkinter.CTkButton(master=self.frame_left, text="CBC",
                                                 fg_color=("gray75", "gray30"),
                                                 command=lambda: self.encryptionModeButtonEvent("CBC", self.CBCButton))
        self.CBCButton.place(x=20, y=200)

        # ECB BUTTON
        self.ECBButton = customtkinter.CTkButton(master=self.frame_left, text="ECB",
                                                 fg_color=("gray75", "gray30"),
                                                 command=lambda: self.encryptionModeButtonEvent("ECB", self.ECBButton))
        self.ECBButton.place(x=20, y=250)

        # CFB BUTTON
        self.CFBButton = customtkinter.CTkButton(master=self.frame_left, text="CFB",
                                                 fg_color=("gray75", "gray30"),
                                                 command=lambda: self.encryptionModeButtonEvent("CFB", self.CFBButton))
        self.CFBButton.place(x=20, y=300)

        # OFB BUTTON
        self.OFBButton = customtkinter.CTkButton(master=self.frame_left, text="OFB",
                                                 fg_color=("gray75", "gray30"),
                                                 command=lambda: self.encryptionModeButtonEvent("OFB", self.OFBButton))
        self.OFBButton.place(x=20, y=350)

        # LIGHT MODE SWITCH
        self.modeSwitch = customtkinter.CTkSwitch(master=self.frame_left, text="Light Mode", command=self.switchMode)
        self.modeSwitch.place(x=20, y=450)

        # MESSAGE BOX
        self.messageBox = tkinter.Label(master=self.frame_right, font=("Helvetica", 12), fg='#fff',
                                        bg=self.frame_left.fg_color[1])
        # WIDTH 700
        self.messageBox.grid(padx=25, pady=25)

        # MESSAGE INPUT
        self.messageInput = customtkinter.CTkEntry(master=self.frame_right, width=550,
                                                   placeholder_text="Send a message")
        self.messageInput.place(y=500, x=20)

        # FILE BUTTON
        self.fileButton = customtkinter.CTkButton(master=self.frame_right, text="FILE",
                                                  fg_color=("gray75", "gray30"),
                                                  command=lambda: self.openFile())
        self.fileButton.place(y=450, x=600)

        # CLIENT BUTTON
        self.sendButton = customtkinter.CTkButton(master=self.frame_right, text="SEND", fg_color=("gray75", "gray30"),
                                                  command=self.handleSending)
        self.sendButton.place(y=500, x=600)

        self.encryptionButtons.extend([self.CBCButton, self.ECBButton, self.CFBButton, self.OFBButton])
        self.encryptionModeButtonEvent("CBC", self.CBCButton)

    def getServer(self):
        return self.server

    def getClient(self):
        return self.client

    def setServer(self, server):
        self.server = server

    def setClient(self, client):
        self.client = client

    def serverButtonEvent(self, HOST_IP, SERVER_PORT):
        if self.serverButton.fg_color != self.serverButton.hover_color:
            # TURN ON SERVER
            self.serverButton.config(fg_color=self.serverButton.hover_color)
            succeed = self.setUpServer(HOST_IP, SERVER_PORT)
            if succeed is False:
                # ERROR IN CONNECTING
                self.serverButton.config(fg_color=self.sendButton.fg_color)
        else:
            # TURN OFF SERVER
            self.serverButton.config(fg_color=self.sendButton.fg_color)
            self.server.shutDown()

    def clientButtonEvent(self, HOST_IP, RECIPIENT_IP, CLIENT_PORT):
        if self.clientButton.fg_color != self.clientButton.hover_color:
            # TURN ON CLIENT
            self.clientButton.config(fg_color=self.clientButton.hover_color)
            succeed = self.setUpClient(HOST_IP, RECIPIENT_IP, CLIENT_PORT)
            if succeed is False:
                # ERROR IN CONNECTING
                self.clientButton.config(fg_color=self.sendButton.fg_color)
        else:
            # TURN OFF CLIENT
            self.clientButton.config(fg_color=self.sendButton.fg_color)
            self.client.shutDown()

    def encryptionModeButtonEvent(self, AES_MODE, encryptionButton):
        self.encryptionButton = encryptionButton

        if self.encryptionButton.fg_color != self.encryptionButton.hover_color:
            for button in self.encryptionButtons:
                button.config(fg_color=self.sendButton.fg_color)
            self.encryptionButton.config(fg_color=self.encryptionButton.hover_color)
            self.encryptor.switchEncryptionMode(AES_MODE)

        elif encryptionButton is not self.CBCButton:
            self.encryptionButton.config(fg_color=self.sendButton.fg_color)
            self.CBCButton.config(fg_color=self.encryptionButton.hover_color)
            self.encryptor.switchEncryptionMode("CBC")
        else:
            # Can't turn off CBC MODE
            pass

    def openFile(self):
        self.fileHandler = FileHandler()
        self.fileHandler.openFileDialog()

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

    def setUpServer(self, HOST_IP, SERVER_PORT):
        logger = Logger(self)
        self.server = Server(HOST_IP, SERVER_PORT, logger, self.encryptor)
        succeed = self.server.run()
        if succeed is True:
            return True
        else:
            return False

    def setUpClient(self, HOST_IP, RECIPIENT_IP, CLIENT_PORT):
        logger = Logger(self)
        self.client = Client(HOST_IP, CLIENT_PORT, logger, self.encryptor)
        succeed = self.client.connect(RECIPIENT_IP)
        if succeed is True:
            return True
        else:
            return False

    def run(self):
        # print("GUI: " + str(threading.current_thread().getName()))
        self.mainloop()

    def shutDown(self):
        if self.client is not None:
            self.client.shutDown()
        if self.server is not None:
            self.server.shutDown()
        self.encryptor.destroyKeys()
        sys.exit(0)
