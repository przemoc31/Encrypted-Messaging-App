MAIN_CLIENT_PORT = 2022
MAIN_SERVER_PORT = 2023
ROB_CLIENT_PORT = 2023
ROB_SERVER_PORT = 2022


MSG_LENGTH = 1024

MAIN_PRIVATE_KEY_PATH = "mainKeys/private_key.pem"
MAIN_PUBLIC_KEY_PATH = "mainKeys/public_key.pem"
ROB_PRIVATE_KEY_PATH = "robKeys/private_key.pem"
ROB_PUBLIC_KEY_PATH = "robKeys/public_key.pem"

HOST_IP = '192.168.42.37'
RECIPIENT_IP = '192.168.42.37'
#HOST_IP = '192.168.0.158'
#RECIPIENT_IP = '192.168.0.158'

ACK_MESSAGE = f"Server {HOST_IP} received a message"
ACK_ERROR_MESSAGE = f"Server {RECIPIENT_IP} failed to decrypt the message! " \
                    f"Check if you are using a good encryption mode!"

SESSION_KEY_LENGTH = 32
