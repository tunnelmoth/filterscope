"""wgcheck — does a UDP VPN work on this network: a real WireGuard handshake.

Uses your own WireGuard config: sends a handshake initiation (Noise_IKpsk2); if the
server returns a response (type 2) → WireGuard WORKS on this network. No reply →
the endpoint/UDP is blocked or the config is wrong.

Only works against your own VPN server (your key must be configured as a peer).

Usage:
  filterscope wg --config /etc/wireguard/wg0.conf
  filterscope wg --endpoint vpn.example.com:51820 --server-pubkey <b64> --private-key <b64>
"""
import argparse
import base64
import hashlib
import hmac
import os
import socket
import sys
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"


def H(*parts):
    h = hashlib.blake2s()
    for p in parts:
        h.update(p)
    return h.digest()


def HMAC(key, msg):
    return hmac.new(key, msg, hashlib.blake2s).digest()


def KDF(key, inp, n):
    t = HMAC(key, inp)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = HMAC(t, prev + bytes([i]))
        out.append(prev)
    return out


def DH(priv, pub):
    return priv.exchange(X25519PublicKey.from_public_bytes(pub))


def mac16(key, msg):
    return hashlib.blake2s(msg, key=key, digest_size=16).digest()


def tai64n():
    now = time.time()
    secs = int(now) + 0x400000000000000A
    nanos = int((now - int(now)) * 1e9)
    return secs.to_bytes(8, "big") + nanos.to_bytes(4, "big")


def aead(key, counter, pt, aad):
    nonce = b"\x00" * 4 + counter.to_bytes(8, "little")
    return ChaCha20Poly1305(key).encrypt(nonce, pt, aad)


def build_initiation(spub_r, spriv_raw):
    """WireGuard whitepaper §5.4.2 handshake initiation."""
    spriv = X25519PrivateKey.from_private_bytes(spriv_raw)
    spub_i = spriv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ci = H(CONSTRUCTION)
    hi = H(ci + IDENTIFIER)
    hi = H(hi + spub_r)
    epriv = X25519PrivateKey.generate()
    epub = epriv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    (ci,) = KDF(ci, epub, 1)
    hi = H(hi + epub)
    ci, k = KDF(ci, DH(epriv, spub_r), 2)
    enc_static = aead(k, 0, spub_i, hi)
    hi = H(hi + enc_static)
    ci, k = KDF(ci, DH(spriv, spub_r), 2)
    enc_ts = aead(k, 0, tai64n(), hi)
    hi = H(hi + enc_ts)
    sender = os.urandom(4)
    body = b"\x01\x00\x00\x00" + sender + epub + enc_static + enc_ts  # 116 bytes
    m1 = mac16(H(LABEL_MAC1 + spub_r), body)
    return body + m1 + b"\x00" * 16  # +mac1 +mac2(0) = 148 bytes


def parse_config(path):
    priv = pub = endpoint = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.lower().startswith("privatekey"):
                priv = line.split("=", 1)[1].strip()
            elif line.lower().startswith("publickey"):
                pub = line.split("=", 1)[1].strip()
            elif line.lower().startswith("endpoint"):
                endpoint = line.split("=", 1)[1].strip()
    return priv, pub, endpoint


def main(argv=None):
    ap = argparse.ArgumentParser(prog="filterscope wg", description="WireGuard handshake reachability test")
    ap.add_argument("--config", help="wg conf file")
    ap.add_argument("--endpoint", help="host:port")
    ap.add_argument("--server-pubkey", help="server public key (base64)")
    ap.add_argument("--private-key", help="your private key (base64)")
    ap.add_argument("--timeout", type=float, default=5)
    ap.add_argument("--tries", type=int, default=3)
    a = ap.parse_args(argv)

    priv, pub, endpoint = a.private_key, a.server_pubkey, a.endpoint
    if a.config:
        cpriv, cpub, cendp = parse_config(a.config)
        priv, pub, endpoint = priv or cpriv, pub or cpub, endpoint or cendp
    if not (priv and pub and endpoint):
        sys.exit("missing: --config or --endpoint + --server-pubkey + --private-key")

    try:
        spriv_raw = base64.b64decode(priv)
        spub_r = base64.b64decode(pub)
        assert len(spriv_raw) == 32 and len(spub_r) == 32
    except Exception:
        sys.exit("key is not 32-byte base64")

    host, _, port = endpoint.rpartition(":")
    try:
        ip = socket.gethostbyname(host)
    except OSError as e:
        sys.exit(f"could not resolve endpoint: {e}")
    port = int(port)
    print(f"WireGuard handshake → {host}:{port} ({ip})")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(a.timeout)
    for i in range(1, a.tries + 1):
        pkt = build_initiation(spub_r, spriv_raw)
        try:
            s.sendto(pkt, (ip, port))
            data, _ = s.recvfrom(1500)
            if data[:4] == b"\x02\x00\x00\x00":
                print(f"✓ WORKS — handshake response received (try {i}, {len(data)} bytes)")
                return
            print(f"  unexpected reply: type={data[0]}")
        except socket.timeout:
            print(f"  try {i}: no reply")
        except OSError as e:
            print(f"  error: {type(e).__name__}")
            break
    print("✗ BLOCKED/unreachable — no handshake response "
          "(UDP/endpoint blocked or config wrong)")
    sys.exit(1)


if __name__ == "__main__":
    main()
