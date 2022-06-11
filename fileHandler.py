from tkinter import filedialog
from globals import MSG_FILE_LENGTH
import time


class FileHandler:
    fileName = None
    content = None
    extension = None

    def openFileDialog(self):
        file = filedialog.askopenfile(mode='rb', filetypes=[('Text files', '*.txt'),
                                                            ('Images', '*.png'),
                                                            ('Documents', '*.pdf'),
                                                            ('Videos', '*.avi')])
        self.readFromFile(file)

    def readFromFile(self, file):
        if file is not None:
            self.content = file.read()
            filePath = file.name
            self.fileName = filePath.rsplit('/', 1)[-1]
            print(self.fileName)

    def openFile(self, fileName):
        file = open(fileName, 'ab')
        return file

    def saveToFile(self, message, file):
        file.write(message)
        time.sleep(0.000001)

    def closeFile(self, file):
        file.close()
