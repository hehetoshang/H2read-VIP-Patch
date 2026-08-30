#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H2read-VIP-Patch / import_license.py
====================================
通过 adb (root) 把离线许可证写入设备上的 App SharedPreferences, 无需改源码。

用法:
  1) 安装补丁版 APK:   adb install out/patched.apk
  2) 探测真实机器码:   python3 import_license.py --probe-machine-code
                      (原理: 导入一个错误机器码的许可证, 触发 verifyLicense 的
                       DEVICE_MISMATCH 日志, 日志中会打印 current= 真实机器码)
  3) 签发许可证:       python3 keygen.py issue --device <真实机器码> \
                          --key forge/private.pem --permanent --out out/perm_lic.txt
  4) 导入:             python3 import_license.py --lic out/perm_lic.txt

其他:
  --clear      清除本地许可证 (恢复未激活)
  --show       显示当前 prefs 内容
  --launch     导入后启动 App
  --package    包名 (默认 com.lowh202.sevennovel)

说明:
  - 需要 root 权限的 adb 设备/模拟器 (adb root)
  - 导入前自动 force-stop, 防止 SharedPreferences 内存缓存覆盖
  - 保留原有 prefs 键 (first_launch_time / trial_granted 等), 只增改许可证键
"""

import argparse
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

PKG_DEFAULT = "com.lowh202.sevennovel"
PREFS_NAME = "h2read_vip_prefs"
LIC_KEY = "offline_rsa_license"
PREFS_DIR = "/data/data/%s/shared_prefs" % PKG_DEFAULT
PREFS_XML = "%s/%s.xml" % (PREFS_DIR, PREFS_NAME)


def adb(*args, check=True, text=True):
    cmd = ["adb"] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=text)
    if check and r.returncode != 0:
        sys.exit(f"[!] adb 命令失败: {' '.join(cmd)}\n    {r.stderr.strip()}")
    return r.stdout.strip()


def root_check():
    out = adb("root", check=False)
    # 等待 adbd 重启
    if "restarting" in out.lower() or "adbd" in out.lower():
        time.sleep(3)
        adb("wait-for-device")
    who = adb("shell", "id", "-u")
    if who != "0":
        sys.exit("[!] 需要 root (adb root 不可用? 请使用 root 模拟器/设备)")


def read_prefs_xml():
    raw = adb("shell", "cat", PREFS_XML, check=False)
    if "No such file" in raw or raw == "":
        return None
    return raw


def build_xml(entries, lic):
    lines = ["<?xml version='1.0' encoding='utf-8' standalone='yes' ?>", "<map>"]
    for k, v in entries:
        lines.append(f'    <string name="{k}">{v}</string>')
    if lic:
        lines.append(f'    <string name="{LIC_KEY}">{lic}</string>')
    lines.append("</map>")
    return "\n".join(lines) + "\n"


def push_license(lic):
    adb("shell", "am", "force-stop", PKG_DEFAULT)
    # 读取现有 prefs 条目 (防止覆盖丢失 first_launch_time 等)
    entries = []
    raw = read_prefs_xml()
    if raw and "<map>" in raw:
        try:
            root = ET.fromstring(raw)
            for el in root.findall("string"):
                k = el.get("name")
                if k and k != LIC_KEY:
                    entries.append((k, el.text or ""))
        except ET.ParseError:
            print("[!] 解析现有 prefs 失败, 将重建 (丢失试用状态, 不影响 VIP)")
    new_xml = build_xml(entries, lic)
    tmp = "/data/local/tmp/h2read_prefs.xml"
    tmp_push = Path(tempfile.gettempdir()) / "h2read_prefs_push.xml"
    with open(tmp_push, "w") as f:
        f.write(new_xml)
    subprocess.run(["adb", "push", str(tmp_push), tmp], check=True, capture_output=True)
    adb("shell", "mkdir", "-p", PREFS_DIR)
    uid = adb("shell", "dumpsys", "package", PKG_DEFAULT, check=False)
    user_id = None
    for line in uid.splitlines():
        if "userId=" in line:
            user_id = line.split("userId=")[1].split()[0]
            break
    adb("shell", "cp", tmp, PREFS_XML)
    if user_id:
        adb("shell", "chown", f"{user_id}:{user_id}", PREFS_XML)
    adb("shell", "chmod", "660", PREFS_XML)
    adb("shell", "rm", tmp)
    print(f"[+] 许可证已写入 {PREFS_XML}")
    print(f"[+] 许可证: {lic[:60]}...")
    return user_id


def probe_machine_code():
    """导入错误机器码许可证 -> 触发 DEVICE_MISMATCH 日志 -> 日志含真实机器码"""
    # 先用 keygen 签发一个 dummy 机器码的许可证 (离线, 用攻击者私钥)
    key = "forge/private.pem"
    if not Path(key).exists():
        sys.exit("[!] 缺少 forge/private.pem, 请先: python3 keygen.py gen-keys --out forge/")
    lic_path = str(Path(tempfile.gettempdir()) / "h2read_dummy_lic.txt")
    subprocess.run([sys.executable, "keygen.py", "issue",
                    "--device", "H2R-DUMMY-0000-0000-0000",
                    "--key", key, "--permanent", "--out", lic_path],
                   check=True, capture_output=True)
    lic = Path(lic_path).read_text().strip()
    push_license(lic)
    adb("shell", "monkey", "-p", PKG_DEFAULT, "-c", "android.intent.category.LAUNCHER", "1", check=False)
    print("[*] 已注入 dummy 许可证并启动 App, 等待 8 秒收集日志...")
    time.sleep(8)
    log = adb("logcat", "-d", "-s", "VipManager:*", "AndroidRuntime:E", check=False)
    print("--- logcat (VipManager) ---")
    print(log)
    print("----------------------------")
    print("[*] 从上面日志中找到类似行:")
    print("    License device mismatch: lic=H2R-DUMMY-..., current=<真实机器码>")
    print("[*] 然后执行:")
    print("    python3 keygen.py issue --device <真实机器码> --key forge/private.pem --permanent --out out/perm_lic.txt")
    print("    python3 import_license.py --lic out/perm_lic.txt")


def main():
    ap = argparse.ArgumentParser(description="离线许可证导入器 (adb root)")
    ap.add_argument("--lic", help="许可证文件路径 (keygen.py issue 输出)")
    ap.add_argument("--probe-machine-code", action="store_true", help="探测设备真实机器码")
    ap.add_argument("--clear", action="store_true", help="清除本地许可证")
    ap.add_argument("--show", action="store_true", help="显示当前 prefs")
    ap.add_argument("--launch", action="store_true", help="导入后启动 App")
    ap.add_argument("--package", default=PKG_DEFAULT)
    args = ap.parse_args()

    if not (args.lic or args.probe_machine_code or args.clear or args.show):
        ap.print_help()
        sys.exit(1)

    root_check()

    if args.show:
        raw = read_prefs_xml()
        print(raw if raw else "[空]")
        return

    if args.clear:
        adb("shell", "am", "force-stop", args.package)
        new_xml = build_xml([], None)
        tmp_push = Path(tempfile.gettempdir()) / "h2read_prefs_push.xml"
        with open(tmp_push, "w") as f:
            f.write(new_xml)
        subprocess.run(["adb", "push", str(tmp_push), "/data/local/tmp/h2read_prefs.xml"],
                       check=True, capture_output=True)
        adb("shell", "cp", "/data/local/tmp/h2read_prefs.xml", PREFS_XML)
        print("[+] 许可证已清除")
        return

    if args.probe_machine_code:
        probe_machine_code()
        return

    if args.lic:
        lic = Path(args.lic).read_text().strip()
        if not lic.startswith("LIC."):
            sys.exit("[!] 许可证格式错误, 应以 LIC. 开头")
        push_license(lic)
        if args.launch:
            adb("shell", "monkey", "-p", args.package, "-c", "android.intent.category.LAUNCHER", "1", check=False)
        print("[+] 完成。打开 App 即可看到 VIP 已激活。")


if __name__ == "__main__":
    main()
