#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H2read-VIP-Patch / patch_apk.py
===============================
对已编译的 release APK 做纯二进制补丁 (不修改任何源码, 独立程序)

补丁原理 (两条信任链同时替换):
  [A] DEX 信任根替换
      解析 classes*.dex 字符串池, 把 App 内置 RSA-2048 公钥 (392 字符 Base64)
      等长替换为攻击者公钥 -> 之后任何攻击者私钥签发的许可证都能通过离线验签
      (替换后按 dex 规范重算 checksum(Adler-32) 与 signature(SHA-1), 保证 dexopt 通过)

  [B] native 签名校验绕过
      重签名后的 APK 证书哈希 != 内置 EXPECTED_SIG, 会把机器码降级为随机 UUID
      且 isEnvironmentSafe=false 导致 hasVipAccess 恒 false (有声书播放被拒)
      因此把 lib/*/libh2sec.so 中的 64 位证书哈希等长替换为攻击者 keystore
      证书的 SHA-256 -> 重签名后 native 校验通过, 硬件机器码正常计算

依赖 (可选, 自动检测):
  keytool (JDK)       生成攻击者 keystore / 导出证书算哈希
  zipalign            重打包后 4 字节对齐 (SDK build-tools)
  apksigner           重签名 v1+v2 (SDK build-tools)

用法:
  1) 生成攻击者密钥对 (只需一次):
     python3 keygen.py gen-keys --out forge/
  2) 打补丁:
     python3 patch_apk.py --apk app-universal-release.apk \
         --pub forge/public.pem \
         --keystore out/attack.jks --alias hack --pass hack123 \
         --out out/patched.apk
  3) 安装 + 导入许可证 (见 import_license.py / README.md)

还原: 原始 APK 不受影响 (只读输入)。
"""

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path

# App 内置原始公钥 (用于 dex 定位) 与原始签名哈希 (用于 so 定位)
ORIG_PUB_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuCc4KD7OWh2IAcZnpk5u"
    "CA3/+3kXk9Z6Mx/AxitJ+pthHCToizflV1nIqkqJwHrmEwJ+shFlYUamOoO6dfqX"
    "K6dJ2DlCSZ/oFuTlz4nynhWDmpR4OGyG2GhOEJnwOji/RgzrEmfxKN3d1Rfzuzlm"
    "DZFdF9b/hEKpbd2hZN6abNGegUIK9MQHcxSuY/3t+2w64ejTC4RNuOHOj3kaEDkD"
    "EH34KBciLP5IEfpRetax39gsuk+/QUxrwplZzN8eYVZobiNo8gfE1jVGLxDt4/Gc"
    "s3pgnRwDblfOBAaEZ1iunqKL1W/6iuo7K9F3sls7DY+AOt5MZTpz/9jr7v+NYyAd"
    "6wIDAQAB"
)
ORIG_SIG_HASH = "fc26e7a61c7bd4a58e89d8036c26ce47ea1debcda884fe16dc1008471ad06519"


def fmt_pub_pem(b64: str) -> str:
    """Kotlin 三引号字符串在 dex 中的真实形态: 前导换行 + 每 64 字符一行 + 结尾换行"""
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n" + "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# DEX 解析与等长字符串替换
# ---------------------------------------------------------------------------

class DexFile:
    """轻量 DEX 解析器: 定位并等长替换字符串池条目, 重算校验和"""

    def __init__(self, data: bytes):
        self.data = bytearray(data)
        if self.data[:4] != b"dex\n":
            raise ValueError("not a dex file")
        self.file_size = struct.unpack_from("<I", self.data, 0x20)[0]
        self.string_ids_size = struct.unpack_from("<I", self.data, 0x38)[0]
        self.string_ids_off = struct.unpack_from("<I", self.data, 0x3C)[0]

    def _uleb128(self, off):
        result = 0
        shift = 0
        while True:
            b = self.data[off]
            off += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result, off
            shift += 7

    def iter_strings(self):
        for i in range(self.string_ids_size):
            off = self.string_ids_off + i * 4
            s_off = struct.unpack_from("<I", self.data, off)[0]
            utf16_len, p = self._uleb128(s_off)
            start = p
            while self.data[p] != 0:
                p += 1
            yield i, utf16_len, start, p  # (id, utf16_len, data_start, data_end_excl_null)

    def replace_ascii(self, target: str, replacement: str) -> bool:
        """等长替换 ASCII 字符串 (MUTF-8 下 ASCII 与 UTF-8 编码一致)"""
        if len(target) != len(replacement):
            raise ValueError("replacement must be same length as target")
        tb = target.encode("utf-8")
        rb = replacement.encode("utf-8")
        found = False
        for i, utf16_len, start, end in self.iter_strings():
            if end - start != len(tb):
                continue
            if bytes(self.data[start:end]) == tb:
                self.data[start:end] = rb
                found = True
        return found

    def finalize(self):
        """重算 signature (SHA-1 of bytes 32..) 与 checksum (Adler-32 of bytes 12..)"""
        self.data[12:32] = hashlib.sha1(bytes(self.data[32:])).digest()
        self.data[8:12] = struct.pack("<I", zlib.adler32(bytes(self.data[12:])))
        return bytes(self.data)

    @staticmethod
    def verify_checksum(data: bytes) -> bool:
        return struct.unpack_from("<I", data, 8)[0] == (
            zlib.adler32(data[12:]) & 0xFFFFFFFF
        ) and data[12:32] == hashlib.sha1(data[32:]).digest()


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

def find_tool(names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    # SDK build-tools 兜底
    for bt in sorted(Path("/opt/android-sdk/build-tools").glob("*"), reverse=True):
        for n in names:
            p = bt / n
            if p.exists():
                return str(p)
    return None


def gen_keystore(ks_path: str, alias: str, password: str):
    if os.path.exists(ks_path):
        print(f"[*] 复用 keystore: {ks_path}")
        return
    os.makedirs(os.path.dirname(ks_path), exist_ok=True)
    keytool = find_tool(["keytool"])
    if not keytool:
        sys.exit("[!] 找不到 keytool (JDK)")
    cmd = [keytool, "-genkeypair", "-keystore", ks_path, "-alias", alias,
           "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
           "-storepass", password, "-keypass", password,
           "-dname", "CN=H2Read Crack, OU=CTF, O=H2Read, L=SH, C=CN"]
    subprocess.run(cmd, check=True, capture_output=True)
    print(f"[+] 生成攻击者 keystore: {ks_path}")


def cert_sha256(ks_path: str, alias: str, password: str) -> str:
    """导出 keystore 证书 DER, 计算 SHA-256 (即 native checkApkSignature 比对值)"""
    keytool = find_tool(["keytool"])
    tmp = tempfile.NamedTemporaryFile(suffix=".der", delete=False)
    tmp.close()
    subprocess.run([keytool, "-exportcert", "-keystore", ks_path, "-alias", alias,
                    "-storepass", password, "-file", tmp.name],
                   check=True, capture_output=True)
    cert = Path(tmp.name).read_bytes()
    os.unlink(tmp.name)
    return hashlib.sha256(cert).hexdigest()


# ---------------------------------------------------------------------------
# 补丁流程
# ---------------------------------------------------------------------------

def patch_dex(work: Path, pub_b64: str) -> int:
    """替换所有 classes*.dex 中的 RSA 公钥, 返回替换的文件数"""
    n = 0
    target = fmt_pub_pem(ORIG_PUB_B64)
    replacement = fmt_pub_pem(pub_b64)
    if len(target) != len(replacement):
        raise ValueError("公钥排版后长度不一致 (需同为 2048 位 RSA SPKI)")
    for dex_path in sorted(work.glob("classes*.dex")):
        dex = DexFile(dex_path.read_bytes())
        if dex.replace_ascii(target, replacement):
            dex_path.write_bytes(dex.finalize())
            assert DexFile.verify_checksum(dex_path.read_bytes()), f"checksum failed: {dex_path}"
            print(f"  [OK] {dex_path.name}: RSA 公钥已替换 (+校验和已重算)")
            n += 1
        else:
            print(f"  [..] {dex_path.name}: 未找到公钥 (跳过)")
    return n


def patch_so(work: Path, new_hash: str) -> int:
    """替换各 ABI libh2sec.so 中的 EXPECTED_SIG 哈希 (等长 64 hex)"""
    n = 0
    if len(new_hash) != 64 or not re.fullmatch(r"[0-9a-f]{64}", new_hash):
        raise ValueError("证书哈希必须是 64 位十六进制")
    for so in sorted(work.glob("lib/*/libh2sec.so")):
        data = so.read_bytes()
        if ORIG_SIG_HASH.encode() in data:
            so.write_bytes(data.replace(ORIG_SIG_HASH.encode(), new_hash.encode()))
            print(f"  [OK] {so}: 签名哈希已替换")
            n += 1
        else:
            print(f"  [..] {so}: 未找到原始哈希 (跳过)")
    return n


def repack_apk(apk_in: Path, work: Path, apk_out: Path):
    """按原压缩方式重打包 APK"""
    with zipfile.ZipFile(apk_in) as zin:
        infos = {i.filename: i for i in zin.infolist()}
        with zipfile.ZipFile(apk_out, "w") as zout:
            for name, info in sorted(infos.items()):
                data = zin.read(name)
                # 已补丁文件从 work/ 取
                src = work / name
                if src.exists() and src.is_file():
                    data = src.read_bytes()
                zi = zipfile.ZipInfo(name, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zout.writestr(zi, data)
    print(f"[+] 重打包: {apk_out}")


def main():
    ap = argparse.ArgumentParser(description="H2read release APK 二进制补丁器 (CTF, 不改源码)")
    ap.add_argument("--apk", required=True, help="目标 release APK")
    ap.add_argument("--pub", default="forge/public.pem", help="攻击者公钥 PEM")
    ap.add_argument("--keystore", default="out/attack.jks", help="攻击者 keystore (不存在则生成)")
    ap.add_argument("--alias", default="hack", help="keystore 别名")
    ap.add_argument("--pass", dest="password", default="hack123", help="keystore 密码")
    ap.add_argument("--out", default="out/patched.apk", help="输出 APK")
    ap.add_argument("--keep-work", action="store_true", help="保留解包目录")
    args = ap.parse_args()

    apk_in = Path(args.apk).resolve()
    if not apk_in.exists():
        sys.exit(f"[!] 找不到目标 APK: {apk_in}")

    pub_b64 = "".join(l.strip() for l in Path(args.pub).read_text().splitlines()
                      if l.strip() and "-----" not in l)
    if len(pub_b64) != len(ORIG_PUB_B64):
        sys.exit(f"[!] 公钥长度 {len(pub_b64)} != 原始 {len(ORIG_PUB_B64)}, 必须同为 2048 位 RSA SPKI")
    if pub_b64 == ORIG_PUB_B64:
        sys.exit("[!] 公钥与原始相同, 请先用 keygen.py gen-keys 生成新密钥对")

    tools = {t: find_tool([t]) for t in ("keytool", "zipalign", "apksigner")}
    missing = [t for t, p in tools.items() if not p]
    if missing:
        sys.exit(f"[!] 缺少工具: {missing} (需要 JDK keytool + SDK build-tools 的 zipalign/apksigner)")

    work = Path(tempfile.mkdtemp(prefix="apk_patch_"))
    print(f"[*] 目标 APK: {apk_in}")
    print(f"[*] 工作目录: {work}")

    # 1. 解包
    with zipfile.ZipFile(apk_in) as z:
        z.extractall(work)
    print(f"[*] 解包完成, dex: {len(list(work.glob('classes*.dex')))} 个, so: {len(list(work.glob('lib/*/libh2sec.so')))} 个")

    # 2. keystore + 证书哈希
    gen_keystore(args.keystore, args.alias, args.password)
    new_hash = cert_sha256(args.keystore, args.alias, args.password)
    print(f"[*] 攻击者证书 SHA-256: {new_hash}")

    # 3. dex 公钥替换
    print("[A] DEX 信任根替换:")
    if patch_dex(work, pub_b64) == 0:
        sys.exit("[!] 所有 dex 均未找到公钥, 请确认 APK 版本")

    # 4. so 签名哈希替换
    print("[B] native 签名哈希替换:")
    if patch_so(work, new_hash) == 0:
        print("[!] 警告: 未找到 libh2sec.so (补丁后机器码将降级为随机 UUID, 且 isEnvironmentSafe=false)")

    # 5. 重打包 + 对齐 + 签名
    aligned = Path(str(apk_in) + ".aligned.apk")
    repack_apk(apk_in, work, aligned)
    aligned2 = Path(str(apk_in) + ".aligned2.apk")
    subprocess.run([tools["zipalign"], "-f", "4", str(aligned), str(aligned2)],
                   check=True, capture_output=True)
    os.unlink(aligned)
    aligned = aligned2
    print("[+] zipalign 完成")
    apk_out = Path(args.out).resolve()
    os.makedirs(apk_out.parent, exist_ok=True)
    subprocess.run([tools["apksigner"], "sign",
                    "--ks", args.keystore, "--ks-key-alias", args.alias,
                    "--ks-pass", f"pass:{args.password}", "--key-pass", f"pass:{args.password}",
                    "--out", str(apk_out), str(aligned)],
                   check=True, capture_output=True)
    os.unlink(aligned)
    print(f"[+] 签名完成: {apk_out}")

    # 6. 自检
    print("[*] 自检:")
    r = subprocess.run([tools["apksigner"], "verify", "--print-certs", str(apk_out)],
                       capture_output=True, text=True)
    print("  " + r.stdout.strip().replace("\n", "\n  "))
    with zipfile.ZipFile(apk_out) as z:
        for name in z.namelist():
            if name.startswith("classes") and name.endswith(".dex"):
                data = z.read(name)
                assert DexFile.verify_checksum(data), f"dex checksum invalid: {name}"
                status = "已替换" if fmt_pub_pem(pub_b64).encode() in data else "未找到!"
                print(f"  [dex] {name}: 公钥 {status}")
            elif name.endswith("libh2sec.so"):
                data = z.read(name)
                status = "已替换" if new_hash.encode() in data else "未找到!"
                print(f"  [so ] {name}: 签名哈希 {status}")

    if not args.keep_work:
        shutil.rmtree(work, ignore_errors=True)

    print("\n[+] 补丁完成。下一步:")
    print(f"    adb install {apk_out}")
    print("    然后: python3 import_license.py --lic <许可证文件> (见 README.md)")


if __name__ == "__main__":
    main()
