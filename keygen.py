#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H2read-VIP-Patch / keygen.py
============================
离线许可证伪造器 (CTF 工具)

功能:
  gen-keys   生成 RSA-2048 攻击者密钥对 (公钥 SPKI PEM / 私钥 PKCS#8 PEM)
  issue      离线签发 LIC.<Base64(JSON Payload)>.<Base64(RSA Signature)> 许可证
  verify     用公钥离线验签 (完整复刻 VipManager.verifyLicense 的校验逻辑)

算法兼容性:
  - 签名: RSASSA-PKCS1-v1_5 with SHA-256, 即 Java/Android 的 "SHA256withRSA"
  - 密钥: RSA-2048, e=65537, 与 App 内置 RSA_PUBLIC_KEY_PEM 同规格
  - 编码: 标准 Base64 (Android Base64.DEFAULT), payload 为 UTF-8 JSON
  - 纯 Python 标准库实现, 无第三方依赖

用法:
  python3 keygen.py gen-keys  --out forge/
  python3 keygen.py issue     --device H2R-XXXX-XXXX-XXXX-XXXX \
                              --key forge/private.pem --permanent --out lic.txt
  python3 keygen.py verify    --license "$(cat lic.txt)" --pub forge/public.pem

许可证 Payload 字段 (与 App 解析完全一致):
  machine_id / device_id  机器码 (二选一, 忽略大小写比对)
  expire_time             过期 Unix 时间戳; >= 9999999999 视为永久
  vip_type                "permanent" 视为永久
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time

# ---------------------------------------------------------------------------
# 基础数学
# ---------------------------------------------------------------------------

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("modular inverse does not exist")
    return x % m

def is_probable_prime(n, rounds=24):
    """Miller-Rabin 素性测试"""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        cand = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(cand):
            return cand

# ---------------------------------------------------------------------------
# DER / PEM 编码 (标准库手写, 对齐 Java X509EncodedKeySpec / PKCS8)
# ---------------------------------------------------------------------------

def der_len(n):
    """DER 长度字段最小编码"""
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def der_tlv(tag, content):
    return bytes([tag]) + der_len(len(content)) + content

def der_int(x):
    if x == 0:
        b = b"\x00"
    else:
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return der_tlv(0x02, b)

def der_bit_string(content):
    return der_tlv(0x03, b"\x00" + content)

def der_octet_string(content):
    return der_tlv(0x04, content)

def der_seq(*items):
    return der_tlv(0x30, b"".join(items))

RSA_OID = bytes.fromhex("06092a864886f70d010101")

def read_pem(path):
    with open(path, "r") as f:
        b64 = "".join(line.strip() for line in f
                      if line.strip() and not line.strip().startswith("-----"))
    return base64.b64decode(b64)

def public_spki_der(n, e):
    """SubjectPublicKeyInfo (X509EncodedKeySpec 期望的格式)"""
    return der_seq(
        der_seq(RSA_OID, der_tlv(0x05, b"")),          # AlgorithmIdentifier
        der_bit_string(der_seq(der_int(n), der_int(e))),  # BIT STRING { n, e }
    )

def private_pkcs8_der(n, e, d, p, q):
    """PKCS#8 PrivateKeyInfo, 内含 PKCS#1 RSAPrivateKey"""
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = modinv(q, p)
    pkcs1 = der_seq(
        der_int(0), der_int(n), der_int(e), der_int(d),
        der_int(p), der_int(q), der_int(dp), der_int(dq), der_int(qinv),
    )
    return der_seq(
        der_int(0),                                       # version
        der_seq(RSA_OID, der_tlv(0x05, b"")),             # AlgorithmIdentifier
        der_octet_string(pkcs1),                          # RSAPrivateKey
    )

def pem_wrap(der, label):
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"

def parse_spki(der):
    """解析 SubjectPublicKeyInfo, 返回 (n, e)"""
    # 仅做轻量解析: 定位 BIT STRING 内容
    # SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQ { INT n, INT e } } }
    assert der[0] == 0x30
    idx = 1
    l1, llen1 = _read_len(der, idx)
    idx += llen1
    seq1_end = idx + l1
    # 跳过 AlgorithmIdentifier
    assert der[idx] == 0x30
    l2, llen2 = _read_len(der, idx + 1)
    idx += 1 + llen2 + l2
    assert der[idx] == 0x03, "not a BIT STRING"
    l3, llen3 = _read_len(der, idx + 1)
    idx += 1 + llen3 + 1  # +1 跳过 unused bits 字节
    assert der[idx] == 0x30
    l4, llen4 = _read_len(der, idx + 1)
    idx += 1 + llen4
    # 读取两个 INTEGER
    assert der[idx] == 0x02
    ln, llen_n = _read_len(der, idx + 1)
    n = int.from_bytes(der[idx + 1 + llen_n: idx + 1 + llen_n + ln], "big")
    idx += 1 + llen_n + ln
    assert der[idx] == 0x02
    le, llen_e = _read_len(der, idx + 1)
    e = int.from_bytes(der[idx + 1 + llen_e: idx + 1 + llen_e + le], "big")
    return n, e

def parse_pkcs8(der):
    """解析 PKCS#8 私钥, 返回 (n, e, d, p, q)"""
    # 定位 OCTET STRING 内的 PKCS#1
    assert der[0] == 0x30
    idx = 1
    l1, llen1 = _read_len(der, idx)
    idx += llen1
    # version INTEGER
    assert der[idx] == 0x02
    lv, llen_v = _read_len(der, idx + 1)
    idx += 1 + llen_v + lv
    # AlgorithmIdentifier
    assert der[idx] == 0x30
    la, llen_a = _read_len(der, idx + 1)
    idx += 1 + llen_a + la
    # OCTET STRING
    assert der[idx] == 0x04
    lo, llen_o = _read_len(der, idx + 1)
    idx += 1 + llen_o
    inner = der[idx: idx + lo]
    # 解析 PKCS#1: SEQ { INT 0, INT n, INT e, INT d, INT p, INT q, ... }
    vals = []
    assert inner[0] == 0x30
    l5, llen5 = _read_len(inner, 1)
    i = 1 + llen5
    while i < len(inner):
        assert inner[i] == 0x02
        lv2, llen_v2 = _read_len(inner, i + 1)
        vals.append(int.from_bytes(inner[i + 1 + llen_v2: i + 1 + llen_v2 + lv2], "big"))
        i += 1 + llen_v2 + lv2
    n, e, d, p, q = vals[1], vals[2], vals[3], vals[4], vals[5]
    return n, e, d, p, q

def _read_len(buf, idx):
    first = buf[idx]
    if first < 0x80:
        return first, 1
    n = first & 0x7F
    return int.from_bytes(buf[idx + 1: idx + 1 + n], "big"), 1 + n

# ---------------------------------------------------------------------------
# RSASSA-PKCS1-v1_5 with SHA-256 (Java "SHA256withRSA" 完全等价)
# ---------------------------------------------------------------------------

SHA256_DIGEST_INFO = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)

def emsa_pkcs1_encode(digest, k):
    """EM = 0x00 || 0x01 || PS(0xFF..) || 0x00 || T, 总长 k 字节"""
    t = SHA256_DIGEST_INFO + digest
    if k < len(t) + 11:
        raise ValueError("key too small")
    ps = b"\xff" * (k - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t

def rsa_sign(n, d, data: bytes) -> bytes:
    k = (n.bit_length() + 7) // 8
    digest = hashlib.sha256(data).digest()
    em = emsa_pkcs1_encode(digest, k)
    m = int.from_bytes(em, "big")
    s = pow(m, d, n)
    return s.to_bytes(k, "big")

def rsa_verify(n, e, data: bytes, sig: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    s = int.from_bytes(sig, "big")
    m = pow(s, e, n)
    em = m.to_bytes(k, "big")
    digest = hashlib.sha256(data).digest()
    expected = emsa_pkcs1_encode(digest, k)
    return secrets.compare_digest(em, expected)

# ---------------------------------------------------------------------------
# 许可证 LIC 格式: LIC.<Base64(JSON Payload)>.<Base64(RSA Signature)>
# ---------------------------------------------------------------------------

def build_license(device_machine_id, n, d, expire_time=9999999999, vip_type="permanent", extra=None):
    payload = {
        "machine_id": device_machine_id,
        "expire_time": expire_time,
        "vip_type": vip_type,
    }
    if extra:
        payload.update(extra)
    payload_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = rsa_sign(n, d, payload_json)
    return "LIC." + base64.b64encode(payload_json).decode() + "." + base64.b64encode(sig).decode(), payload

def verify_license(license_str, n, e, check_device=None, verbose=False):
    """完整复刻 VipManager.verifyLicense 的判定顺序"""
    if not license_str or not license_str.strip():
        return "INVALID_SIGN"
    parts = license_str.strip().split(".")
    if len(parts) != 3 or parts[0] != "LIC":
        return "INVALID_SIGN"
    try:
        payload_bytes = base64.b64decode(parts[1])
        sig_bytes = base64.b64decode(parts[2])

        # 1. RSA-2048 + SHA256withRSA 验签 (对解码后的原始 JSON 字节)
        if not rsa_verify(n, e, payload_bytes, sig_bytes):
            if verbose:
                print("[x] RSA signature verification failed")
            return "INVALID_SIGN"

        payload = json.loads(payload_bytes.decode("utf-8"))

        # 2. 机器码绑定 (machine_id 或 device_id)
        target = payload.get("machine_id") or payload.get("device_id") or ""
        if check_device and target.lower() != check_device.lower():
            if verbose:
                print(f"[x] device mismatch: lic={target} current={check_device}")
            return "DEVICE_MISMATCH"

        # 3. 过期时间 (>= 9999999999 或 vip_type=permanent 视为永久)
        exp = payload.get("expire_time") or payload.get("vip_expire_time") or 0
        if exp < 9999999999 and payload.get("vip_type") != "permanent":
            if time.time() > exp:
                if verbose:
                    print(f"[x] expired at {exp}")
                return "EXPIRED"
        if verbose:
            print(f"[ok] VALID: machine_id={target} expire={exp} type={payload.get('vip_type')}")
        return "VALID"
    except Exception as ex:
        if verbose:
            print(f"[x] exception: {ex}")
        return "INVALID_SIGN"

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_gen_keys(args):
    os.makedirs(args.out, exist_ok=True)
    print("[*] 生成 RSA-2048 密钥对 (可能需要几秒)...")
    p = gen_prime(1024)
    q = gen_prime(1024)
    while q == p:
        q = gen_prime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)

    pub_path = os.path.join(args.out, "public.pem")
    priv_path = os.path.join(args.out, "private.pem")
    with open(pub_path, "w") as f:
        f.write(pem_wrap(public_spki_der(n, e), "PUBLIC KEY"))
    with open(priv_path, "w") as f:
        f.write(pem_wrap(private_pkcs8_der(n, e, d, p, q), "PRIVATE KEY"))
    os.chmod(priv_path, 0o600)

    # 自检: 公钥能被 X509EncodedKeySpec 同款格式解析
    nn, ee = parse_spki(read_pem(pub_path))
    assert (nn, ee) == (n, e), "SPKI self-check failed"

    pub_b64 = base64.b64encode(public_spki_der(n, e)).decode()
    print(f"[+] 私钥: {priv_path}")
    print(f"[+] 公钥: {pub_path}  (SPKI, {len(pub_b64)} chars)")
    print(f"[+] 公钥 Base64 (供替换 App 内置 RSA_PUBLIC_KEY_PEM):")
    for i in range(0, len(pub_b64), 64):
        print(f"    {pub_b64[i:i+64]}")


def cmd_issue(args):
    n, e, d, p, q = parse_pkcs8(read_pem(args.key))
    assert (n.bit_length() + 7) // 8 == 256, "密钥必须是 2048 位"
    if args.permanent:
        exp = 9999999999
        vtype = "permanent"
    else:
        exp = int(time.time()) + args.days * 86400
        vtype = "year" if args.days == 365 else ("month" if args.days == 30 else "custom")
    lic, payload = build_license(args.device, n, d, expire_time=exp, vip_type=vtype)
    print(f"[*] Payload: {json.dumps(payload, ensure_ascii=False)}")
    print(f"[+] LIC: {lic}")
    if args.out:
        with open(args.out, "w") as f:
            f.write(lic + "\n")
        print(f"[+] 已写入 {args.out}")
    # 签发后立即用公钥自检
    status = verify_license(lic, n, e, check_device=args.device)
    print(f"[*] 自检验签: {status}")
    if status != "VALID":
        sys.exit(1)


def cmd_verify(args):
    with open(args.license) as f:
        lic = f.read().strip()
    n, e = parse_spki(read_pem(args.pub))
    status = verify_license(lic, n, e, check_device=args.device, verbose=True)
    print(f"RESULT: {status}")
    sys.exit(0 if status == "VALID" else 1)


def main():
    ap = argparse.ArgumentParser(description="H2read VIP 离线许可证伪造器 (CTF)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-keys", help="生成 RSA-2048 攻击者密钥对")
    g.add_argument("--out", default="forge", help="输出目录 (默认 forge/)")
    g.set_defaults(fn=cmd_gen_keys)

    i = sub.add_parser("issue", help="离线签发许可证")
    i.add_argument("--device", required=True, help="目标机器码 H2R-XXXX-XXXX-XXXX-XXXX")
    i.add_argument("--key", required=True, help="私钥 PEM 路径")
    i.add_argument("--days", type=int, default=365, help="有效天数 (默认 365)")
    i.add_argument("--permanent", action="store_true", help="签发永久许可证 (expire=9999999999)")
    i.add_argument("--out", help="输出文件")
    i.set_defaults(fn=cmd_issue)

    v = sub.add_parser("verify", help="离线验签 (复刻 App 逻辑)")
    v.add_argument("--license", required=True, help="许可证文件路径")
    v.add_argument("--pub", required=True, help="公钥 PEM 路径")
    v.add_argument("--device", help="期望机器码 (可选, 模拟 DEVICE_MISMATCH 检查)")
    v.set_defaults(fn=cmd_verify)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
