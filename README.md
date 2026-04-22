# Secure AES C2 Detection
Secure AES-based socket communication framework with C2 behavior detection and behavioral traffic analysis.

---

## Overview

This project implements a secure client-server communication framework using AES-based encryption, combined with detection of malicious Command-and-Control (C2) behavior and behavioral traffic analysis. It simulates real-world malware communication patterns and demonstrates detection, prevention, and forensic validation.

---

## Key Features

* AES-encrypted socket communication
* Authenticated key exchange using Diffie-Hellman and RSA
* Replay attack protection using timestamp and nonce
* Key rotation for forward secrecy
* Hash-based tamper-evident logging
* Behavioral C2 detection based on traffic patterns
* Wireshark-based network-level validation

---

## System Setup

* Client (Ubuntu) and Server (Kali) on separate virtual machines
* Internal network with static IPs for controlled communication
* Isolated environment for accurate traffic analysis

---

## Modules

### Module 0: Basic Pipeline

* TCP communication upgraded to AES (Fernet) encryption
* Simulated C2 beaconing at ~5 second intervals
* Detection based on consistent timing behavior
* Non-blocking sockets used to stabilize intervals
* Improved detection using sliding window and tolerance
* Blocking implemented using INPUT/OUTPUT rules and socket termination

---

### Module 1: Authenticated Key Exchange

* Diffie-Hellman used for secure key exchange
* RSA signatures used for server authentication
* Prevents Man-in-the-Middle (MITM) attacks
* Shared secret converted to symmetric key using HKDF

---

### Module 2: Replay Attack Protection

* Demonstrates replay vulnerability in encrypted systems
* Protection implemented using:

  * Timestamp validation
  * Nonce tracking
* Prevents duplicate and delayed packet reuse

---

### Module 3: Key Rotation

* Periodic re-keying using Diffie-Hellman
* Performed within active session without interruption
* Ensures forward secrecy and limits impact of key compromise

---

### Module 4: Hash-Based Logging

* Log integrity ensured using hash chaining
* Each log depends on previous hash and current event
* Tampering breaks the chain and is detectable
* JSON-based structured logging with verification mechanism

---

### Module 5: Wireshark Analysis

* Confirms encrypted communication (no plaintext visible)
* Identifies periodic beaconing (~5 second intervals)
* Shows structured request-response traffic patterns
* Demonstrates that behavior is detectable even with encryption

---

## Key Insights

* Encryption alone is insufficient without authentication and replay protection
* Behavioral patterns can reveal malicious activity in encrypted traffic
* Key rotation improves long-term security and limits exposure
* Tamper-evident logging is essential for reliable forensic analysis

---

## Technologies Used

* Python
* Socket Programming
* Cryptography (Fernet, Diffie-Hellman, RSA, HKDF)
* Wireshark
* Linux (Kali and Ubuntu VMs)

---

## Screenshots

Screenshots for each module are included within their respective folders.
