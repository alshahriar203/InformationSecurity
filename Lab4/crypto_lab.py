#!/usr/bin/env python3
"""
crypto_lab.py
Single-file tool for:
- AES (128/256) encrypt/decrypt (ECB, CFB)
- RSA encrypt/decrypt
- RSA sign/verify (SHA-256, PKCS#1 v1.5)
- SHA-256 hashing
- Benchmarking (timings + plots)

Dependencies:
    pip install pycryptodome matplotlib
"""

import argparse
import os
import time
import json
import hashlib
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# plotting
import matplotlib.pyplot as plt

# Directories
KEY_DIR = "keys"
DATA_DIR = "data"
PLOT_DIR = "plots"
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(PLOT_DIR, exist_ok=True)

# ---------- Utility helpers ----------
def now_s():
    return time.perf_counter()

def save_bytes(path, b):
    with open(path, "wb") as f:
        f.write(b)

def load_bytes(path):
    with open(path, "rb") as f:
        return f.read()

# ---------- AES helpers (PyCryptodome AES) ----------
BS = AES.block_size  # 16

def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BS - (len(data) % BS)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BS:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def gen_aes_key(bits: int):
    if bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192 or 256")
    return get_random_bytes(bits // 8)

def aes_encrypt_file(key: bytes, infile: str, outfile: str, mode: str):
    start = now_s()
    pdata = load_bytes(infile)
    if mode.upper() == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        ct = cipher.encrypt(pkcs7_pad(pdata))
        # write ciphertext raw
        save_bytes(outfile, ct)
    elif mode.upper() == "CFB":
        iv = get_random_bytes(BS)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        ct = cipher.encrypt(pdata)
        # store iv + ciphertext
        save_bytes(outfile, iv + ct)
    else:
        raise ValueError("Unsupported AES mode: choose ECB or CFB")
    elapsed = now_s() - start
    print(f"AES encrypt done. Wrote {outfile}. Elapsed: {elapsed:.6f} s")
    return elapsed

def aes_decrypt_file(key: bytes, infile: str, mode: str):
    start = now_s()
    data = load_bytes(infile)
    if mode.upper() == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        pt = pkcs7_unpad(cipher.decrypt(data))
    elif mode.upper() == "CFB":
        iv = data[:BS]
        ct = data[BS:]
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)
        pt = cipher.decrypt(ct)
    else:
        raise ValueError("Unsupported AES mode: choose ECB or CFB")
    elapsed = now_s() - start
    print(f"AES decrypt done. Elapsed: {elapsed:.6f} s")
    return pt, elapsed

# ---------- RSA helpers ----------
def gen_rsa_keypair(bits: int):
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    return priv, pub

def rsa_encrypt_file(pubkey_pem: bytes, infile: str, outfile: str):
    start = now_s()
    pub = RSA.import_key(pubkey_pem)
    cipher = PKCS1_OAEP.new(pub)
    pdata = load_bytes(infile)
    # RSA can only encrypt small messages; typically you'll use hybrid encryption.
    # For this lab we will attempt to encrypt the whole file if small, otherwise we chunk or raise.
    # We'll encrypt in small blocks to allow larger files (inefficient but demonstrative).
    mlen = len(pdata)
    # OAEP max message size = key_size_bytes - 2*hash_size - 2; using SHA1 by default in PKCS1_OAEP of PyCryptodome,
    # but library may use SHA-1; to be safe we'll chunk with conservative size:
    kbytes = pub.size_in_bytes()
    # Conservative chunk size:
    max_chunk = kbytes - 42
    if max_chunk <= 0:
        raise ValueError("RSA key too small to encrypt any data")
    chunks = [pdata[i:i+max_chunk] for i in range(0, mlen, max_chunk)]
    pieces = []
    for ch in chunks:
        pieces.append(cipher.encrypt(ch))
    # write concatenated pieces; we will write a JSON header with chunk size to help decryption
    meta = {"chunk_size": max_chunk, "piece_count": len(pieces), "kbytes": kbytes}
    with open(outfile, "wb") as f:
        header = (json.dumps(meta) + "\n").encode("utf-8")
        f.write(header)
        for p in pieces:
            # write length-prefixed chunk to make parsing robust
            plen = len(p).to_bytes(4, "big")
            f.write(plen)
            f.write(p)
    elapsed = now_s() - start
    print(f"RSA encrypt done. Wrote {outfile}. Elapsed: {elapsed:.6f} s")
    return elapsed

def rsa_decrypt_file(privkey_pem: bytes, infile: str):
    start = now_s()
    priv = RSA.import_key(privkey_pem)
    cipher = PKCS1_OAEP.new(priv)
    with open(infile, "rb") as f:
        header_line = f.readline()
        meta = json.loads(header_line.decode("utf-8"))
        pieces = []
        for _ in range(meta["piece_count"]):
            plen_b = f.read(4)
            if not plen_b:
                break
            plen = int.from_bytes(plen_b, "big")
            data = f.read(plen)
            pieces.append(cipher.decrypt(data))
    pdata = b"".join(pieces)
    elapsed = now_s() - start
    print(f"RSA decrypt done. Elapsed: {elapsed:.6f} s")
    return pdata, elapsed

# ---------- RSA signature ----------
def rsa_sign_file(privkey_pem: bytes, infile: str, sigfile: str):
    start = now_s()
    priv = RSA.import_key(privkey_pem)
    data = load_bytes(infile)
    h = SHA256.new(data)
    signature = pkcs1_15.new(priv).sign(h)
    save_bytes(sigfile, signature)
    elapsed = now_s() - start
    print(f"Signature written to {sigfile}. Elapsed: {elapsed:.6f} s")
    return elapsed

def rsa_verify_file(pubkey_pem: bytes, infile: str, sigfile: str):
    start = now_s()
    pub = RSA.import_key(pubkey_pem)
    data = load_bytes(infile)
    signature = load_bytes(sigfile)
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pub).verify(h, signature)
        ok = True
        print("Signature is valid.")
    except (ValueError, TypeError):
        ok = False
        print("Signature is INVALID.")
    elapsed = now_s() - start
    print(f"Verification elapsed: {elapsed:.6f} s")
    return ok, elapsed

# ---------- SHA-256 ----------
def hash_file_sha256(infile: str):
    data = load_bytes(infile)
    h = hashlib.sha256(data).hexdigest()
    print(f"SHA-256({infile}) = {h}")
    return h

# ---------- Benchmarking ----------
def benchmark_aes(keys_bits_list=[128, 192, 256], plaintext_sizes_bytes=[16, 128, 1024, 8192, 65536], mode="CFB"):
    results = {}
    for bits in keys_bits_list:
        key = gen_aes_key(bits)
        times = []
        for size in plaintext_sizes_bytes:
            # make a test file
            fname = os.path.join(DATA_DIR, f"aes_test_{bits}b_{size}b.bin")
            with open(fname, "wb") as f:
                f.write(os.urandom(size))
            out = fname + ".enc"
            t = aes_encrypt_file(key, fname, out, mode)
            times.append(t)
        results[bits] = {"sizes": plaintext_sizes_bytes, "times": times}
    # Plotting: plaintext size (bytes) vs time for each key bit
    for bits, info in results.items():
        plt.plot(info["sizes"], info["times"], marker='o', label=f"AES {bits}b")
    plt.xlabel("Plaintext size (bytes)")
    plt.ylabel("Encryption time (s)")
    plt.xscale("log")
    plt.title(f"AES encryption time vs plaintext size (mode={mode})")
    plt.legend()
    outplot = os.path.join(PLOT_DIR, f"aes_benchmark_{mode}.png")
    plt.savefig(outplot)
    plt.clf()
    print(f"AES benchmark plot saved to {outplot}")
    return results, outplot

def benchmark_rsa(key_sizes=[512, 1024, 2048, 3072, 4096], test_message=b"Benchmark test message"):
    results = {}
    for bits in key_sizes:
        start = now_s()
        priv, pub = gen_rsa_keypair(bits)
        keygen_time = now_s() - start
        # save temporarily
        priv_p = os.path.join(KEY_DIR, f"rsa_private_{bits}.pem")
        pub_p = os.path.join(KEY_DIR, f"rsa_public_{bits}.pem")
        save_bytes(priv_p, priv)
        save_bytes(pub_p, pub)
        # encrypt
        enc_file = os.path.join(DATA_DIR, f"rsa_test_{bits}.bin")
        # write small test message to disk as file
        msgfile = os.path.join(DATA_DIR, f"rsa_msg_{bits}.bin")
        save_bytes(msgfile, test_message)
        enc_time = rsa_encrypt_file(pub, msgfile, enc_file)
        # decrypt
        dec_data, dec_time = rsa_decrypt_file(priv, enc_file)
        assert dec_data == test_message
        results[bits] = {"keygen": keygen_time, "encrypt": enc_time, "decrypt": dec_time}
        print(f"RSA {bits}b: keygen {keygen_time:.4f}s, encrypt {enc_time:.4f}s, decrypt {dec_time:.4f}s")
    # Plot keysize vs times
    sizes = list(results.keys())
    kg = [results[s]["keygen"] for s in sizes]
    en = [results[s]["encrypt"] for s in sizes]
    de = [results[s]["decrypt"] for s in sizes]
    plt.plot(sizes, kg, marker='o', label='keygen')
    plt.plot(sizes, en, marker='o', label='encrypt')
    plt.plot(sizes, de, marker='o', label='decrypt')
    plt.xlabel("RSA key size (bits)")
    plt.ylabel("Time (s)")
    plt.title("RSA timings vs key size")
    plt.legend()
    outplot = os.path.join(PLOT_DIR, "rsa_benchmark.png")
    plt.savefig(outplot)
    plt.clf()
    print(f"RSA benchmark plot saved to {outplot}")
    return results, outplot

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Crypto lab tool (AES, RSA, SHA-256, benchmark)")
    sub = parser.add_subparsers(dest="cmd")

    # gen-aes
    p = sub.add_parser("gen-aes", help="Generate AES key")
    p.add_argument("--bits", type=int, choices=[128,192,256], default=128)

    # aes-encrypt
    p = sub.add_parser("aes-encrypt", help="AES encrypt a file")
    p.add_argument("infile")
    p.add_argument("outfile")
    p.add_argument("--bits", type=int, choices=[128,192,256], default=128)
    p.add_argument("--mode", choices=["ECB","CFB"], default="CFB")

    p = sub.add_parser("aes-decrypt", help="AES decrypt a file")
    p.add_argument("infile")
    p.add_argument("--bits", type=int, choices=[128,192,256], default=128)
    p.add_argument("--mode", choices=["ECB","CFB"], default="CFB")

    # gen-rsa
    p = sub.add_parser("gen-rsa", help="Generate RSA keypair")
    p.add_argument("--bits", type=int, default=2048)

    p = sub.add_parser("rsa-encrypt", help="RSA encrypt a file (public key)")
    p.add_argument("pubkey")
    p.add_argument("infile")
    p.add_argument("outfile")

    p = sub.add_parser("rsa-decrypt", help="RSA decrypt a file (private key)")
    p.add_argument("privkey")
    p.add_argument("infile")

    # sign / verify
    p = sub.add_parser("sign", help="Sign a file with RSA private key")
    p.add_argument("privkey")
    p.add_argument("infile")
    p.add_argument("sigfile")

    p = sub.add_parser("verify", help="Verify signature with RSA public key")
    p.add_argument("pubkey")
    p.add_argument("infile")
    p.add_argument("sigfile")

    # hash
    p = sub.add_parser("hash", help="SHA-256 hash a file")
    p.add_argument("infile")

    # benchmark
    p = sub.add_parser("benchmark", help="Run benchmarks and create plots")
    p.add_argument("--aes-modes", nargs="+", default=["CFB"])
    p.add_argument("--rsa-sizes", nargs="+", type=int, default=[512,1024,2048,3072,4096])

    args = parser.parse_args()

    if args.cmd == "gen-aes":
        key = gen_aes_key(args.bits)
        path = os.path.join(KEY_DIR, f"aes_key_{args.bits}.bin")
        save_bytes(path, key)
        print(f"AES {args.bits}-bit key saved to {path}")

    elif args.cmd == "aes-encrypt":
        keypath = os.path.join(KEY_DIR, f"aes_key_{args.bits}.bin")
        if not os.path.exists(keypath):
            print(f"Key not found: {keypath}. Generate it with gen-aes --bits {args.bits}")
            return
        key = load_bytes(keypath)
        aes_encrypt_file(key, args.infile, args.outfile, args.mode)

    elif args.cmd == "aes-decrypt":
        keypath = os.path.join(KEY_DIR, f"aes_key_{args.bits}.bin")
        if not os.path.exists(keypath):
            print(f"Key not found: {keypath}. Generate it with gen-aes --bits {args.bits}")
            return
        key = load_bytes(keypath)
        pt, t = aes_decrypt_file(key, args.infile, args.mode)
        print("----- Decrypted plaintext (bytes) -----")
        print(pt)
        try:
            print("----- As UTF-8 -----")
            print(pt.decode("utf-8"))
        except:
            pass

    elif args.cmd == "gen-rsa":
        priv, pub = gen_rsa_keypair(args.bits)
        priv_p = os.path.join(KEY_DIR, f"rsa_private_{args.bits}.pem")
        pub_p = os.path.join(KEY_DIR, f"rsa_public_{args.bits}.pem")
        save_bytes(priv_p, priv)
        save_bytes(pub_p, pub)
        print(f"RSA {args.bits}-bit private -> {priv_p}, public -> {pub_p}")

    elif args.cmd == "rsa-encrypt":
        pub = load_bytes(args.pubkey)
        rsa_encrypt_file(pub, args.infile, args.outfile)

    elif args.cmd == "rsa-decrypt":
        priv = load_bytes(args.privkey)
        pt, t = rsa_decrypt_file(priv, args.infile)
        print("----- Decrypted plaintext (bytes) -----")
        print(pt)
        try:
            print("----- As UTF-8 -----")
            print(pt.decode("utf-8"))
        except:
            pass

    elif args.cmd == "sign":
        priv = load_bytes(args.privkey)
        rsa_sign_file(priv, args.infile, args.sigfile)

    elif args.cmd == "verify":
        pub = load_bytes(args.pubkey)
        rsa_verify_file(pub, args.infile, args.sigfile)

    elif args.cmd == "hash":
        hash_file_sha256(args.infile)

    elif args.cmd == "benchmark":
        # AES benchmarks for standard key sizes vs plaintext sizes
        aes_plain_sizes = [16, 128, 1024, 8192, 65536]
        for m in args.aes_modes:
            benchmark_aes(keys_bits_list=[128,192,256], plaintext_sizes_bytes=aes_plain_sizes, mode=m)
        # RSA benchmark
        benchmark_rsa(key_sizes=args.rsa_sizes)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

