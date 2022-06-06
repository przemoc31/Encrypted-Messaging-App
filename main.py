from encryptor import Encryptor
from fileHandler import FileHandler
from globals import HOST_IP, RECIPIENT_IP, MAIN_PUBLIC_KEY_PATH, MAIN_PRIVATE_KEY_PATH,\
    MAIN_SERVER_PORT, MAIN_CLIENT_PORT
from GUI import GUI


def main():
    encryptor = Encryptor(MAIN_PRIVATE_KEY_PATH, MAIN_PUBLIC_KEY_PATH)
    encryptor.generateKeys()
    fileHandler = FileHandler()
    gui = GUI(encryptor, fileHandler, HOST_IP, RECIPIENT_IP, MAIN_SERVER_PORT, MAIN_CLIENT_PORT)
    gui.run()


if __name__ == '__main__':
    main()
