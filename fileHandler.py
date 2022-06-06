from tkinter import filedialog


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
            file.close()
            #print(type(self.content))
            #print(self.content)
            #self.saveToFile()

    def saveToFile(self, message, fileName):
        with open(fileName, 'wb') as file:
            decryptedMessage = message
            file.write(decryptedMessage)
