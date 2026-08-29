#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
H2read-VIP-Patch / patch_source.py
==================================
对 H2read-Client 源码自动打 VIP 破解补丁 (源码模式)

补丁内容 (每处均带 [CTF-PATCH] 标记, 便于识别/还原):
  [1] 信任根替换: VipManager.kt 内置 RSA-2048 公钥 → 攻击者公钥
      攻破点: 客户端只持有公钥(信任根), 换根后即可离线自签许可证
  [2] 离线万能卡: redeemCard 支持输入 H2R-FOREVER 本地铸币永久激活
      攻破点: 首次兑换必须联网的限制 (vip_redeem) 被绕过
  [3] 离线许可证导入: redeemCard 支持粘贴 LIC. 开头的字符串直接导入
      配合 keygen.py 签发结果使用, 无需 root / 无需服务端
  [4] ctf_master 放行: verifyLicense 对带 ctf_master 标记的许可证跳过 RSA 验签
      (仍保留机器码绑定检查, 保证万能卡仅对本机有效)
  [5] 机器码日志: init 时输出 machine_code, 便于 keygen 按设备签发绑定许可证
  [6] 签名校验绕过: h2sec.cpp 的 APK 证书 SHA-256 校验
      --bypass-sig 恒真放行 (调试构建) 或 --sig-hash 替换为自有 keystore 哈希

用法:
  python3 patch_source.py --project ../H2read-Client --pub forge/public.pem
  python3 patch_source.py --project ../H2read-Client --pub forge/public.pem --dry-run
  python3 patch_source.py --project ../H2read-Client --pub forge/public.pem --no-master --no-log
  python3 patch_source.py --project ../H2read-Client --sig-hash <64hex>   # 不 bypass, 指定新签名哈希

还原: git -C ../H2read-Client checkout -- app/...  (或 git stash)
"""

import argparse
import re
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# 补丁定义
# ---------------------------------------------------------------------------

def pubkey_patch(pub_b64: str):
    """[1] 替换 VipManager.kt 内置 RSA 公钥"""
    lines = [pub_b64[i:i + 64] for i in range(0, len(pub_b64), 64)]
    new_pem = "\n".join(lines)
    return {
        "file": "app/src/main/java/com/lowh202/sevennovel/data/VipManager.kt",
        "desc": "[1] 替换内置 RSA-2048 公钥为攻击者公钥 (信任根替换)",
        "old": re.compile(
            r'(RSA_PUBLIC_KEY_PEM = """\n)[A-Za-z0-9+/=\n]*(?=\n""")', re.S),
        "new": lambda m: m.group(1) + new_pem,
    }


MASTER_PATCH = {
    "file": "app/src/main/java/com/lowh202/sevennovel/data/VipManager.kt",
    "desc": "[2]+[3] redeemCard 离线万能卡 H2R-FOREVER / 离线许可证导入",
    "old": "        val cleanCode = cardCode.trim().uppercase()",
    "new": """        // [CTF-PATCH] 离线万能卡: 任意设备输入 H2R-FOREVER 直接本地铸币永久激活
        val rawCode = cardCode.trim()
        if (rawCode.equals("H2R-FOREVER", ignoreCase = true)) {
            val payload = JSONObject().apply {
                put("machine_id", getMachineCode(context))
                put("expire_time", 9999999999L)
                put("vip_type", "permanent")
                put("ctf_master", true)
            }
            val lic = "LIC." + Base64.encodeToString(payload.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP) +
                    "." + Base64.encodeToString("ctf-master".toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
            prefs(context).edit().putString(KEY_OFFLINE_LICENSE, lic).apply()
            restoreOfflineLicense(context)
            return@withContext Pair(true, "VIP 永久激活成功（离线万能卡）")
        }
        // [CTF-PATCH] 离线许可证导入: 粘贴 LIC. 开头的字符串直接导入, 无需联网
        if (rawCode.startsWith("LIC.", ignoreCase = true)) {
            prefs(context).edit().putString(KEY_OFFLINE_LICENSE, rawCode).apply()
            val ok = restoreOfflineLicense(context)
            return@withContext if (ok) Pair(true, "离线许可证导入成功") else Pair(false, "许可证无效或设备不匹配")
        }

        val cleanCode = cardCode.trim().uppercase()""",
}


MASTER_VERIFY_PATCH = {
    "file": "app/src/main/java/com/lowh202/sevennovel/data/VipManager.kt",
    "desc": "[4] verifyLicense 放行 ctf_master 标记的本地许可证",
    "old": """        if (parts.size != 3 || parts[0] != "LIC") return LicenseStatus.INVALID_SIGN

        try {""",
    "new": """        if (parts.size != 3 || parts[0] != "LIC") return LicenseStatus.INVALID_SIGN

        // [CTF-PATCH] ctf_master 本地许可证: 跳过 RSA 验签, 但仍校验机器码绑定 (仅本机有效)
        try {
            val masterPayload = JSONObject(String(Base64.decode(parts[1], Base64.DEFAULT), Charsets.UTF_8))
            if (masterPayload.optBoolean("ctf_master", false)) {
                val masterMachine = masterPayload.optString("machine_id", masterPayload.optString("device_id", ""))
                return if (masterMachine.equals(getMachineCode(context), ignoreCase = true)) LicenseStatus.VALID
                else LicenseStatus.DEVICE_MISMATCH
            }
        } catch (_: Throwable) {
            // 解析失败则继续走正常 RSA 验签
        }

        try {""",
}


LOG_PATCH = {
    "file": "app/src/main/java/com/lowh202/sevennovel/data/VipManager.kt",
    "desc": "[5] init 时输出机器码日志 (供 keygen 按设备签发)",
    "old": "        // 2. 优先本地离线许可证验证 (购买的正版 VIP)",
    "new": """        // [CTF-PATCH] 输出当前机器码 (logcat 过滤 VipManager: adb logcat -s VipManager)
        Log.i(TAG, "machine_code=" + getMachineCode(context))

        // 2. 优先本地离线许可证验证 (购买的正版 VIP)""",
}


def sig_bypass_patch():
    return {
        "file": "app/src/main/cpp/h2sec.cpp",
        "desc": "[6] h2sec.cpp APK 签名校验恒真放行 (自签/调试构建可用)",
        "old": "    bool isMatch = (strcasecmp(hexBuffer, EXPECTED_SIG) == 0);",
        "new": "    bool isMatch = true; // [CTF-PATCH] APK 签名校验绕过: 自签构建放行 (原逻辑见 git history)",
    }


def sig_hash_patch(sig_hash: str):
    return {
        "file": "app/src/main/cpp/h2sec.cpp",
        "desc": f"[6] h2sec.cpp 期望签名哈希替换为 {sig_hash}",
        "old": re.compile(
            r'(static const char\* EXPECTED_SIG = ")[0-9a-f]{64}(";)'),
        "new": lambda m: m.group(1) + sig_hash + m.group(2),
    }


# ---------------------------------------------------------------------------
# 补丁执行器
# ---------------------------------------------------------------------------

def apply_patch(file_path: Path, patch, dry_run: bool):
    text = file_path.read_text(encoding="utf-8")
    old = patch["old"]
    if isinstance(old, re.Pattern):
        match = old.search(text)
        if not match:
            print(f"  [SKIP] {patch['desc']} (锚点未找到, 可能已打补丁)")
            return False
        new_text = patch["new"](match)
        patched = old.sub(lambda m: new_text, text, count=1)
    else:
        if old not in text:
            print(f"  [SKIP] {patch['desc']} (锚点未找到, 可能已打补丁)")
            return False
        if isinstance(patch["new"], str):
            new_text = patch["new"]
        else:
            new_text = patch["new"](old)
        patched = text.replace(old, new_text, 1)

    if dry_run:
        print(f"  [DRY-RUN] {patch['desc']}")
        return True
    file_path.write_text(patched, encoding="utf-8")
    print(f"  [OK] {patch['desc']}")
    return True


def main():
    ap = argparse.ArgumentParser(description="H2read 源码 VIP 破解补丁器 (CTF)")
    ap.add_argument("--project", default="../H2read-Client", help="H2read-Client 项目根目录")
    ap.add_argument("--pub", default="forge/public.pem", help="攻击者公钥 PEM (keygen.py gen-keys 产物)")
    ap.add_argument("--no-master", action="store_true", help="不打万能卡/导入补丁")
    ap.add_argument("--no-log", action="store_true", help="不打机器码日志补丁")
    ap.add_argument("--dry-run", action="store_true", help="只预览不修改")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--bypass-sig", action="store_true",
                     help="[6] 签名校验恒真放行 (默认启用)")
    grp.add_argument("--sig-hash", metavar="HEX64",
                     help="[6] 把 EXPECTED_SIG 替换为指定 64 位签名哈希 (不 bypass)")
    args = ap.parse_args()

    project = Path(args.project).resolve()
    vmg = project / "app/src/main/java/com/lowh202/sevennovel/data/VipManager.kt"
    if not vmg.exists():
        sys.exit(f"[!] 找不到 {vmg}, 请确认 --project 指向 H2read-Client 根目录")

    # 读取公钥
    pub = Path(args.pub).resolve()
    if not pub.exists():
        sys.exit(f"[!] 找不到公钥 {pub}, 请先运行: python3 keygen.py gen-keys --out forge/")
    pub_b64 = "".join(l.strip() for l in pub.read_text().splitlines()
                      if l.strip() and "-----" not in l)
    if len(pub_b64) != 392:
        sys.exit(f"[!] 公钥长度异常 ({len(pub_b64)}), 必须是 2048 位 RSA SPKI")

    print(f"[*] 目标项目: {project}")
    print(f"[*] 攻击者公钥: {pub} ({len(pub_b64)} chars)")
    print(f"[*] 模式: {'DRY-RUN' if args.dry_run else 'APPLY'}\n")

    patches = [pubkey_patch(pub_b64)]
    if not args.no_master:
        patches.append(MASTER_PATCH)
        patches.append(MASTER_VERIFY_PATCH)
    if not args.no_log:
        patches.append(LOG_PATCH)
    if args.sig_hash:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", args.sig_hash):
            sys.exit("[!] --sig-hash 必须是 64 位十六进制")
        patches.append(sig_hash_patch(args.sig_hash.lower()))
    elif args.bypass_sig or not args.sig_hash:
        # 默认 bypass: 用户大概率使用 debug keystore 构建
        patches.append(sig_bypass_patch())

    # 按文件分组执行
    for patch in patches:
        f = project / patch["file"]
        apply_patch(f, patch, args.dry_run)

    if args.dry_run:
        print("\n[*] 以上为将要应用的补丁。确认后去掉 --dry-run 执行。")
    else:
        print("\n[+] 补丁完成。构建: cd ../H2read-Client && ./gradlew :app:assembleDebug")
        print("[+] 还原: git -C ../H2read-Client checkout -- app/src")


if __name__ == "__main__":
    main()
