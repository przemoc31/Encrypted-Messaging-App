import sys
import threading
import tkinter
import customtkinter
from logger import Logger
from server import Server
from client import Client
from globals import HOST_IP, RECIPIENT_IP


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
