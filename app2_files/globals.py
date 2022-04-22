CLIENT_PORT = 2023
SERVER_PORT = 2022

MSG_LENGTH = 1024

PRIVATE_KEY_PATH = "private_key2.pem"
PUBLIC_KEY_PATH = "public_key2.pem"

HOST_IP = '192.168.0.158'
RECIPIENT_IP = '192.168.0.158'

ACK_MESSAGE = f"Server {HOST_IP} received a message"
ACK_ERROR_MESSAGE = f"Server {RECIPIENT_IP} failed to decrypt the message! " \
                    f"Check if you are using a good encryption mode!"

SESSION_KEY_LENGTH = 32
