# 🔓 Order -- TryHackMe Challenge [XOR Crypto Crack]

**Author:** TheSysRat  
**Script:** `Order-challenge-solve.py`  
**Challenge Link:** [TryHackMe – ORDER](https://tryhackme.com/room/hfb1order)

---

## 🧠 Challenge Summary

This repository contains a Python solution to the **ORDER** challenge on TryHackMe.

> A message encrypted with a repeating-key XOR cipher has been intercepted. It always starts with the header `ORDER:`, which allows us to perform a known-plaintext attack, recover the key, decrypt the message, and extract the flag.

---

## 🛠️ What the Script Does

- Parses a hex-encoded ciphertext.
- Uses the known header `ORDER:` to recover the XOR key.
- Decrypts the entire message using the recovered key.
- Searches for the flag in `THM{...}` format using regex.

---

## 🧩 How to Use

### 🔗 Prerequisites

- Python 3.x

### ▶️ Run the script

```
git clone https://github.com/TheSysRat/Order--THM
cd Order--THM
python3 Order-challenge-solve.py
```
