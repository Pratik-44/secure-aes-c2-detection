import hashlib

LOG_FILE = "secure_log.txt"

def verify_log():
    prev_hash = "0" * 64  # same genesis hash

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    for idx, line in enumerate(lines):
        line = line.strip()

        if not line:
            continue

        try:
            event_part, hash_part = line.rsplit(" | HASH: ", 1)
        except ValueError:
            print(f"[INVALID FORMAT] Line {idx+1}")
            return

        computed_hash = hashlib.sha256(
            prev_hash.encode() + event_part.encode()
        ).hexdigest()

        if computed_hash != hash_part:
            print(f"[TAMPER DETECTED] at line {idx+1}")
            print(f"Expected: {computed_hash}")
            print(f"Found:    {hash_part}")
            return

        prev_hash = computed_hash

    print("[✓] Log integrity verified. No tampering detected.")

if __name__ == "__main__":
    verify_log()
