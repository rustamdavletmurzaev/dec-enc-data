"""
    python script.py genprkey
    python script.py genprkey 2048
    python script.py enc secret.txt secret.bin 0123...ABCD
    python script.py dec secret.bin 0123...ABCD
"""

import sys
import os
import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# ---------- Base58 (for WIF) ----------
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    out = b""
    while n > 0:
        n, r = divmod(n, 58)
        out = B58_ALPHABET[r:r + 1] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[0:1] * pad + out).decode()


def b58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


# ---------- Key ----------
def privkey_to_wif(priv: bytes) -> str:
    # WIF mainnet, uncompressed: 0x80 + 32 bytes + checksum
    return b58check_encode(b'\x80' + priv)


def privkey_to_hex(priv: bytes) -> str:
    return priv.hex().upper()


def hex_to_privkey(hex_str: str) -> bytes:
    hex_str = hex_str.strip()
    if len(hex_str) != 64:
        raise ValueError("Private key must be 64 hex characters (32 bytes)")
    return bytes.fromhex(hex_str)


# ---------- Encryption (AES-256-GCM, key derived from private key via HKDF) ----------
def derive_aes_key(priv: bytes, salt: bytes = b"myapp-v1") -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"aes-256-gcm-data-key",
    )
    return hkdf.derive(priv)


# ---------- Commands ----------
def cmd_genprkey(salt_len_str="100"):
    try:
        salt_len = int(salt_len_str)
        if salt_len < 8:
            salt_len = 100
    except ValueError:
        salt_len = 100

    salt_view = ''.join(secrets.choice(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    ) for _ in range(salt_len))

    print(f"[+] Salt (extra entropy for display, length {salt_len}):")
    print(salt_view)
    print()

    # 256-bit private key, Bitcoin-style
    priv = secrets.token_bytes(32)

    # Ensure the key is valid for secp256k1 (regenerate otherwise)
    while True:
        try:
            ec.derive_private_key(int.from_bytes(priv, 'big'), ec.SECP256K1())
            break
        except ValueError:
            priv = secrets.token_bytes(32)

    print("=" * 20 + " PRIVATE KEY (256-bit, Bitcoin-style) " + "=" * 20)
    print(f"HEX: {privkey_to_hex(priv)}")
    print(f"WIF: {privkey_to_wif(priv)}")
    print("=" * 72)
    print("\n[!] Use HEX or WIF for enc/dec. Save it - the key is not stored to disk.")


def cmd_enc(in_file, out_file, key_str):
    try:
        priv = hex_to_privkey(key_str) if len(key_str) == 64 else None
    except Exception:
        priv = None
    if priv is None:
        # Try interpreting as WIF (starts with 5, length ~52)
        try:
            raw = b58decode_check(key_str)
            if raw[0] != 0x80 or len(raw) != 33:
                raise ValueError
            priv = raw[1:]
        except Exception:
            print("[!] Invalid key format. Expected HEX(64) or WIF.")
            return

    with open(in_file, "rb") as f:
        data = f.read()

    aes_key = derive_aes_key(priv)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, data, None)

    # File format: b"CHK1" + nonce(12) + ct
    with open(out_file, "wb") as f:
        f.write(b"CHK1" + nonce + ct)
    print(f"[+] Encrypted -> {out_file} ({len(ct)} bytes of ciphertext)")


def cmd_dec(in_file, key_str):
    try:
        priv = hex_to_privkey(key_str) if len(key_str) == 64 else None
    except Exception:
        priv = None
    if priv is None:
        try:
            raw = b58decode_check(key_str)
            if raw[0] != 0x80 or len(raw) != 33:
                raise ValueError
            priv = raw[1:]
        except Exception:
            print("[!] Invalid key format. Expected HEX(64) or WIF.")
            return

    with open(in_file, "rb") as f:
        blob = f.read()

    if not blob.startswith(b"CHK1") or len(blob) < 4 + 12:
        print("[!] This file was not created by this script.")
        return

    nonce = blob[4:16]
    ct = blob[16:]

    aes_key = derive_aes_key(priv)
    aesgcm = AESGCM(aes_key)
    try:
        pt = aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[!] Decryption failed (wrong key or corrupted file): {e}")
        return

    # stdout only - no writing to disk
    print("\n" + "=" * 20 + " DECRYPTED DATA " + "=" * 20)
    sys.stdout.buffer.write(pt)
    sys.stdout.buffer.flush()
    print("\n" + "=" * 56)

    # Best-effort wipe of the buffer
    pt = b"\x00" * len(pt)


# Base58 decode for WIF
def b58decode(s: str) -> bytes:
    n = 0
    for ch in s.encode():
        idx = B58_ALPHABET.find(bytes([ch]))
        if idx < 0:
            raise ValueError("bad base58")
        n = n * 58 + idx
    # Restore leading zeros
    pad = 0
    for b in s.encode():
        if b == B58_ALPHABET[0]:
            pad += 1
        else:
            break
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b""
    return b"\x00" * pad + full


def b58decode_check(s: str) -> bytes:
    data = b58decode(s)
    payload, checksum = data[:-4], data[-4:]
    check = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if not hmac.compare_digest(checksum, check):
        raise ValueError("bad checksum")
    return payload


# ---------- Dispatcher ----------
def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python script.py genprkey [salt_length]")
        print("  python script.py enc <in_file> <out_file> <HEX|WIF>")
        print("  python script.py dec <in_file> <HEX|WIF>")
        return

    cmd = sys.argv[1]
    if cmd == "genprkey":
        cmd_genprkey(sys.argv[2] if len(sys.argv) > 2 else "100")
    elif cmd == "enc" and len(sys.argv) >= 5:
        cmd_enc(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "dec" and len(sys.argv) >= 4:
        cmd_dec(sys.argv[2], sys.argv[3])
    else:
        print("[!] Invalid arguments. See usage above.")


if __name__ == "__main__":
    main()
