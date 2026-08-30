# H2read-VIP-Patch — 氢电子书 VIP 离线破解工具集 (CTF)

> **目标结论**：App 的「VIP 激活码（卡密）」本身**不是**离线算法 ——
> 卡密首次兑换必须联网（`POST /api/account.php?action=vip_redeem`），服务端核销后签发
> `offline_license` 返回客户端保存；真正离线的是**许可证的 RSA 验签**。
> 本工具集以纯二进制补丁方式（**不修改任何源码**）攻破该离线链路。

---

## 1. 攻防全景

### 1.1 原版离线验签链路（`VipManager.kt`）

```
卡密 + 机器码
    │  ↓ 联网 POST vip_redeem (首次兑换, 不可离线)
    ▼
服务端核销卡密, 用 license_private.pem 签发 offline_license
    │  ↓ 保存到本地 SharedPreferences (h2read_vip_prefs/offline_rsa_license)
    ▼
客户端以后离线验签 (RSA-2048 公钥 + SHA256withRSA)

离线许可证格式:  LIC.<Base64(JSON Payload)>.<Base64(RSA Signature)>
验证步骤 (verifyLicense, 顺序执行):
  1. 内置 RSA-2048 公钥执行 SHA256withRSA 验签, 签名对象是解码后的原始 JSON 字节
  2. JSON 中 machine_id / device_id 必须与当前设备机器码相同 (忽略大小写)
  3. 检查 expire_time / vip_expire_time (配合单向递增防回滚时间戳)
  4. expire_time >= 9999999999 或 vip_type == "permanent" 视为永久 VIP
典型 payload:  {"machine_id":"H2R-XXXX-XXXX-XXXX-XXXX","expire_time":1788000000,"vip_type":"year"}
```

### 1.2 机器码与 native 防线（`h2sec.cpp` / `SecurityEngine.kt`）

| 组件 | 机制 | 攻破方式 |
|---|---|---|
| 机器码 | `SHA-256(AID + Bootloader序列号 + Widevine deviceUniqueId + BOARD/HARDWARE/BRAND/MODEL/MANUFACTURER/DEVICE/BOOTLOADER + 固定盐)` 取前 16 hex → `H2R-XXXX-XXXX-XXXX-XXXX`，native 计算，不落盘 | 无需攻破：许可证由 keygen 按真实机器码签发 |
| APK 签名校验 | `checkApkSignature` 对 `Signature.toByteArray()` 做 SHA-256 与内置 `fc26e7...6519`（**明文字符串，位于 .so 中**）比对；失败 → 机器码降级为随机 12 位 UUID + `isEnvironmentSafe=false` → `hasVipAccess` 恒 false（有声书播放被拒） | `.so` 内 64 位等长字符串替换为攻击者证书哈希 |
| 反调试/反 Hook | TracerPid / maps 中的 frida/xposed/dobby 等 / 27042 端口 / gum-js-loop 线程 | 正常设备无痕迹，无需处理 |
| 信任根 | 客户端仅内置公钥，无私钥；私钥在服务端仓库（不在本仓库） | **替换信任根**：dex 字符串池内公钥等长替换为攻击者公钥 |
| 首次兑换 | `redeemCard` 联网，无法离线激活 | 绕过兑换：keygen 离线签发 → 直接注入本地 prefs |

### 1.3 破解链（无源码，纯二进制）

```
原始 release APK
   │  patch_apk.py
   │   ├─ [A] classes.dex  字符串池: RSA 公钥 等长替换 → 攻击者公钥 (信任根替换)
   │   ├─ [B] lib/*/libh2sec.so  : EXPECTED_SIG 64hex 等长替换 → 攻击者证书 SHA-256
   │   ├─ zipalign 4 字节对齐
   │   └─ apksigner 用攻击者 keystore 重签名 (v1+v2)
   ▼
patched.apk  ── adb install ──►  设备
   │
   │  import_license.py --probe-machine-code  (注入 dummy 许可证 → 触发
   │    DEVICE_MISMATCH 日志 → logcat 泄出真实机器码 current=H2R-XXXX-...)
   ▼
keygen.py issue --device <真实机器码> --permanent
   ▼
LIC.…(用攻击者私钥签名, 永不过期, 绑定该设备)…  ──  import_license.py --lic 导入
   ▼
App 重启 → restoreOfflineLicense → 攻击者公钥验签通过 → 永久 VIP
```

---

## 2. 工具清单

| 工具 | 作用 | 依赖 |
|---|---|---|
| `keygen.py` | 生成 RSA-2048 攻击者密钥对；离线签发/验签 LIC 许可证（纯标准库，与 `SHA256withRSA` 完全兼容） | 无 |
| `patch_apk.py` | **不改源码**，对 release APK 做 dex 公钥替换 + .so 签名哈希替换 + 重打包 + zipalign + 重签名 | JDK `keytool`、SDK `zipalign`/`apksigner` |
| `import_license.py` | adb(root) 注入许可证到 `h2read_vip_prefs.xml`（合并保留原键）；`--probe-machine-code` 探测真实机器码 | adb + root 设备/模拟器 |
| `patch_source.py` | 备用方案：直接改 H2read-Client 源码（万能卡 `H2R-FOREVER` 离线铸币、LIC 粘贴导入、日志、签名放行） | 源码 + 构建链 |
| `test/JavaCompatCheck.java` | 用 Java `X509EncodedKeySpec` + `SHA256withRSA` 交叉验证密钥/签名与 App 完全兼容 | JDK |

---

## 3. 无源码破解全流程

```bash
# ① 生成攻击者密钥对 (一次即可)
python3 keygen.py gen-keys --out forge/

# ② 对 release APK 打二进制补丁
python3 patch_apk.py --apk app-universal-release.apk \
    --pub forge/public.pem --keystore out/attack.jks \
    --alias hack --pass hack123 --out out/patched.apk

# ③ 安装 (root 模拟器/设备)
adb install out/patched.apk

# ④ 探测设备真实机器码 (利用 DEVICE_MISMATCH 日志泄出 current= 值)
python3 import_license.py --probe-machine-code
#    日志中出现: License device mismatch: lic=H2R-DUMMY-..., current=H2R-XXXX-XXXX-XXXX-XXXX

# ⑤ 按真实机器码签发永久许可证
python3 keygen.py issue --device H2R-XXXX-XXXX-XXXX-XXXX \
    --key forge/private.pem --permanent --out out/perm_lic.txt

# ⑥ 导入设备 (force-stop → 合并写 prefs → 重启)
python3 import_license.py --lic out/perm_lic.txt --launch
```

**可选：限时许可证**（演示到期判定）：
```bash
python3 keygen.py issue --device H2R-XXXX-XXXX-XXXX-XXXX \
    --key forge/private.pem --days 30 --out out/30d_lic.txt
```

**本地验签自检**（复刻 App 判定顺序，含机器码绑定/过期检查）：
```bash
python3 keygen.py verify --license out/perm_lic.txt --pub forge/public.pem --device H2R-XXXX-XXXX-XXXX-XXXX
# RESULT: VALID  (篡改签名 → INVALID_SIGN, 错误机器码 → DEVICE_MISMATCH)
```

---

## 4. 已实测验证项

| 验证点 | 结果 |
|---|---|
| keygen 密钥格式：SPKI 公钥可被 Java `X509EncodedKeySpec` 解析 | ✅ |
| 签名算法：`SHA256withRSA` 交叉验证（Java `Signature` 全通过） | ✅ |
| 正/负向验签：VALID / INVALID_SIGN(篡改) / DEVICE_MISMATCH | ✅ |
| dex 公钥等长替换 + checksum(Adler-32)/signature(SHA-1) 重算 | ✅ 独立实现交叉复核一致 |
| `.so` 双 ABI（arm64-v8a / armeabi-v7a）签名哈希等长替换 | ✅ |
| apksigner v1+v2 重签名，证书 SHA-256 与 .so 内替换值一致 | ✅ |
| 闭环：patched.apk 内新公钥 → Java 验签 keygen 签发许可证 | ✅ |
| 设备侧注入/机器码探测（adb） | 需 root 设备实测 |

---

## 5. 防御加固建议（作者视角）

1. **公钥白盒化**：内置公钥是纯字符串，极易定位替换。应拆散存储 + 运行时拼装 + native 层持有，并对 dex 关键类做 R8 字符串加密/混淆。
2. **签名校验哈希入库**：`EXPECTED_SIG` 是 .so 内明文，等长替换即可绕过。应拆成字节数组异或编码（源码里 `ENC_SIG_HASH` 已有雏形但实际未使用），并周期性换签。
3. **许可证与账号/网络对账**：离线许可证无法防"换信任根"，但服务端 `vip_query` 定期校准可发现本地被篡改；关键特权（有声书）可要求"最近 N 天内至少一次服务端成功校准"。
4. **机器码泄漏面**：`DEVICE_MISMATCH` 日志直接泄出 `current=` 机器码，是本次探测的关键。日志应脱敏。
5. **导入面**：root 设备可直接写 SharedPreferences。可对许可证做服务端+本地双重校验、加本地加密存储（EncryptedSharedPreferences）、并检测 prefs 文件被外部修改。
6. **防重打包**：除证书哈希外，可校验 APK 文件哈希/odex，检测 `zipalign` 后字节差异；native 层对自身代码段完整性做运行时校验（现有 rwxp 检测仅覆盖 inline hook 场景）。

---

## 6. 附：源码模式（备用）

若持有源码且允许修改（自研调试），`patch_source.py` 可一键打补丁并重新构建：
```bash
python3 patch_source.py --project ../H2read-Client --pub forge/public.pem
cd ../H2read-Client && ./gradlew :app:assembleDebug
```
补丁包含：公钥替换、`H2R-FOREVER` 离线万能卡（本地铸币，跳过 RSA 验签但仍绑定机器码）、
`LIC.` 粘贴离线导入、机器码日志、native 签名校验放行。所有改动带 `[CTF-PATCH]` 标记，`git checkout` 可还原。
（注意：该模式修改了源码，与"另作独立程序"的目标不同，仅作攻防对照实验。）

---

*仅供授权测试与学习。攻防同一套系统，破解点即加固点。*
