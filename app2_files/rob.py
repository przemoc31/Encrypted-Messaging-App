from encryptor import Encryptor
from GUI import GUI


def main():
    encryptor = Encryptor()
    encryptor.generateKeys()
    gui = GUI(encryptor)
    gui.run()


if __name__ == '__main__':
    main()
