from tkinter import filedialog


class FileHandler:
    filename = None
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
            file.close()
            print(type(self.content))
            print(self.content)
            self.saveToFile()

    def saveToFile(self):
        f = open('random.pdf', 'wb')
        myByteArray = bytearray(self.content)
        f.write(myByteArray)
        f.close()
