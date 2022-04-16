class Logger:
    gui = None

    def __init__(self, gui):
        self.gui = gui

    def log(self, text):
        self.gui.messageBox.config(text=self.gui.messageBox.cget("text") + text + "\n")
