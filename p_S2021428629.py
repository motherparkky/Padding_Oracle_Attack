#!/usr/bin/env python3

import sys
from oracle_python_v1_2 import pad_oracle

def normalize_oracle_response(ok):
   
    if isinstance(ok, bytes):
        try:
            s = ok.decode(errors='ignore').strip()
        except Exception:
            return 0
        return 1 if s == '1' else 0
    if isinstance(ok, str):
        s = ok.strip()
        return 1 if s == '1' else 0
    if isinstance(ok, bool):
        return 1 if ok else 0
    try:
        return 1 if int(ok) == 1 else 0
    except Exception:
        return 0

BLOCKSIZE = 8

def hex_to_bytes_safe(s: str) -> bytes:
    if not isinstance(s, str):
        raise TypeError("Input must be a string")
    s = s.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    s = s.replace(" ", "")

    if len(s) % 2 != 0:
        s = '0' + s
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise ValueError("Invalid hex string") from e
    
def hex_to_bytes_block(s:str, expected_len_bytes: int = BLOCKSIZE) -> bytes:
    b = hex_to_bytes_safe(s)
    if len(b) != expected_len_bytes:
        raise ValueError(f"Input must be {expected_len_bytes} bytes long")
    return b

def bytes_to_hex_prefixed(b: bytes) -> str:
    return '0x' + b.hex()

def recover_block(C0_bytes, C1_bytes):
    
    assert len(C0_bytes) == BLOCKSIZE
    assert len(C1_bytes) == BLOCKSIZE

    C0 = bytearray(C0_bytes)
    recovered_intermediate = [None] * BLOCKSIZE
    recovered_plaintext = [None] * BLOCKSIZE

    C1_hex = bytes_to_hex_prefixed(bytes(C1_bytes))

    def build_prefix_for_index(idx, pad_len):
        prefix = bytearray(C0)
        for j in range(BLOCKSIZE - 1, idx, -1):
            prefix[j] = recovered_intermediate[j] ^ pad_len
        return prefix

    def dfs(idx):
        if idx < 0:
            return True

        pad_len = BLOCKSIZE - idx
        prefix_base = build_prefix_for_index(idx, pad_len)

        candidates = []
        for guess in range(256):
            prefix_try = bytearray(prefix_base)
            prefix_try[idx] = C0[idx] ^ guess ^ pad_len
            C0_try_hex = bytes_to_hex_prefixed(bytes(prefix_try))
            try:
                ok = pad_oracle(C0_try_hex, C1_hex)
            except Exception as e:
                print("Oracle call error:", e)
                print("Launch bridge process if not running.\nType > java -cp pad_oracle.jar:bcprov-jdk15-130.jar:python_interface_v1_2.jar python_interface_v1_2")
                sys.exit(1)
            if normalize_oracle_response(ok) == 1:
                intermediate_byte = C0[idx] ^ guess
                candidates.append(intermediate_byte)

        if not candidates:
            return False

        for intermediate_byte in candidates:
            recovered_intermediate[idx] = intermediate_byte
            recovered_plaintext[idx] = intermediate_byte ^ C0[idx]

            if dfs(idx - 1):
                return True


        recovered_intermediate[idx] = None
        recovered_plaintext[idx] = None
        return False

    success = dfs(BLOCKSIZE - 1)
    if not success:
        raise RuntimeError("Failed to recover block (no valid padding candidates lead to full solution).")

    return bytes(bytearray(recovered_plaintext))

def remove_pkcs7_padding(p: bytes) -> bytes:
    if len(p) == 0:
        return p
    pad = p[-1]
    if pad < 1 or pad > BLOCKSIZE:
        raise ValueError("Invalid padding value when stripping.")
    if p[-pad:] != bytes([pad]) * pad:
        raise ValueError("Invalid padding bytes when stripping")
    return p[:-pad]

def attack(C0_hex: str, C1_hex: str):
    C0 = hex_to_bytes_block(C0_hex, BLOCKSIZE)
    C1 = hex_to_bytes_block(C1_hex, BLOCKSIZE)

    print("Starting padding oracle attack ...")
    recovered = recover_block(C0, C1)
    print("Raw recovered bytes", recovered.hex())
    
    try:
        plain = remove_pkcs7_padding(recovered)
        try:
            printable = plain.decode('ascii')
        except Exception:
            printable = repr(plain)
        print("Recovered plaintext ", printable)
    except ValueError as e:
        print("Warning: could not strip padding safely", e)
        try:
            print("Recovered plain text as ASCII attempt: ", recovered.decode('ascii', errors='replace'))
        except Exception:
            print("Recovered plaintext bytes: ", recovered)

    return recovered

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python p_S2021428629.py 0xC0HEX 0xC1HEX")
        sys.exit(1)

    C0_hex = sys.argv[1]
    C1_hex = sys.argv[2]

    try:
        attack(C0_hex, C1_hex)
    except Exception as exc:
        print("Attack failed:", exc)
        sys.exit(1)