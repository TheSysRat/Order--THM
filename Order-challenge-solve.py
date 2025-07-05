import re

def xor_decrypt(data: bytes, key: bytes) -> bytes:
return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def find_flag(text: str):
match = re.search(r'THM\{[^}]+\}', text)
return match.group(0) if match else None

def main():
# Intercepted hex message (2 lines combined)
hex_message = (
"1c1c01041963730f31352a3a386e24356b3d32392b6f6b0d323c22243f6373"
"1a0d0c302d3b2b1a292a3a38282c2f222d2a112d282c31202d2d2e24352e60"
)

# Convert hex to bytes
cipher_bytes = bytes.fromhex(hex_message)

# Known plaintext at the start: "ORDER:"
known_plaintext = b"ORDER:"

# Recover key using known plaintext
key = bytes([c ^ p for c, p in zip(cipher_bytes[:len(known_plaintext)], known_plaintext)])

print(f"[+] Recovered key (hex): {key.hex()}")
print(f"[+] Recovered key (ASCII): {''.join(chr(b) if 32 <= b < 127 else '.' for b in key)}")

# Decrypt entire message
decrypted = xor_decrypt(cipher_bytes, key)
decrypted_text = decrypted.decode('utf-8', errors='replace')

print("\n[+] Decrypted message:")
print(decrypted_text)

# Try to find the flag
flag = find_flag(decrypted_text)
if flag:
print(f"\n🏁 FLAG FOUND: {flag}")
else:
print("\n[!] Flag not found in message.")

if __name__ == "__main__":
main()
