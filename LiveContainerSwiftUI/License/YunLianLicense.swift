//
//  YunLianLicense.swift
//  云连 · 授权内核（对应无敌抢单 guard_src/code.js + core.js）
//
//  一机一码：激活码内嵌「机器标签」并 HMAC 签名，12 位 Crockford Base32。
//  机器特征码存 Keychain：删 App 重装不变；抹机后 Keychain 清空会变（需重新授权）。
//
//  码结构（60 bit → 12 字符）：
//    [ver:4][mtag:32][mac:24]
//    - ver  ：格式版本，固定 2
//    - mtag ：SHA256("mt::" + 机器码) 前 4 字节，把码钉死在这台机器
//    - mac  ：HMAC-SHA256(密钥, ver||mtag) 前 3 字节
//
//  真正的闸门是远程清单（卡密必须登记为 =1 才放行，STRICT 模式）。
//

import Foundation
import CryptoKit
import Security

enum YunLianLicense {
    // MARK: - 常量（与发码工具/网页版三处同步）

    /// Crockford Base32 字母表（剔除 I/L/O/U）
    static let alphabet: [Character] = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    /// 格式版本
    static let ver: Int = 2
    /// 码长（不含分隔符）
    static let codeLength: Int = 12
    /// 签名密钥（XOR+Base64 编码态，运行时还原）
    static let keyEnc = "UcMdVhSmSttlzqgxbH57WzUHxl4sx3K/XODOedjWKXQ="
    /// XOR 密钥字节
    static let kb: [UInt8] = [63, 138, 28, 125, 146, 180, 14, 101]

    /// 校验清单地址（XOR+Base64 编码态；与 build 脚本同步）
    static let eURL = "V/5oDeGOIUpY42gY95ptClKlaxLg2mcIXvozGvXAfBFLpW4c5ZtjBEz+eQ+940o0e6RoBeY="

    // MARK: - 密钥

    private static var _key: SymmetricKey?

    static func signingKey() -> SymmetricKey {
        if let k = _key { return k }
        let raw = Data(base64Encoded: keyEnc) ?? Data()
        let out = Data(raw.enumerated().map { $0.element ^ kb[$0.offset % kb.count] })
        let k = SymmetricKey(data: out)
        _key = k
        return k
    }

    // MARK: - XOR 解码（对应 core.js 的 dec）

    static func dec(_ s: String) -> String {
        guard let buf = Data(base64Encoded: s) else { return "" }
        let out = Data(buf.enumerated().map { $0.element ^ kb[$0.offset % kb.count] })
        return String(data: out, encoding: .utf8) ?? ""
    }

    // MARK: - 机器码

    static func normMachine(_ s: String) -> String {
        return s.uppercased().filter { $0.isNumber || ($0 >= "A" && $0 <= "Z") }
    }

    /// 机器标签：SHA256("mt::" + 机器码) 前 4 字节
    static func machineTag(_ displayCode: String) -> Data {
        let n = normMachine(displayCode)
        let d = Data(SHA256.hash(data: Data(("mt::" + n).utf8)))
        return d.prefix(4)
    }

    /// 激活码归一：大写、去分隔符、常见误抄字母纠正
    static func normCode(_ s: String) -> String {
        return s.uppercased()
            .filter { $0.isNumber || ($0 >= "A" && $0 <= "Z") }
            .replacingOccurrences(of: "I", with: "1")
            .replacingOccurrences(of: "L", with: "1")
            .replacingOccurrences(of: "O", with: "0")
    }

    // MARK: - 激活码生成/校验（对应 code.js）

    private static func bytesToBits(_ buf: Data) -> String {
        return buf.map { String($0, radix: 2).padLeft(toLength: 8, withPad: "0") }.joined()
    }

    private static func bitsToBytes(_ bits: String) -> Data {
        var out = Data()
        var idx = bits.startIndex
        while idx < bits.endIndex {
            let end = bits.index(idx, offsetBy: 8, limitedBy: bits.endIndex) ?? bits.endIndex
            let byte = UInt8(bits[idx..<end], radix: 2) ?? 0
            out.append(byte)
            idx = end
        }
        return out
    }

    private static func mac(_ ver: Int, _ mtag: Data) -> Data {
        let msg = Data([UInt8(ver)]) + mtag
        let code = HMAC<SHA256>.authenticationCode(for: msg, using: signingKey())
        return Data(code).prefix(3)
    }

    /// 用机器标签生成激活码（与发码工具同逻辑，客户端仅自检/测试用）
    static func encodeCode(tag: Data) -> String {
        let m = mac(ver, tag)
        let bits = String(ver, radix: 2).padLeft(toLength: 4, withPad: "0")
            + bytesToBits(tag)
            + bytesToBits(m)
        var s = ""
        var idx = bits.startIndex
        while idx < bits.endIndex {
            let end = bits.index(idx, offsetBy: 5, limitedBy: bits.endIndex) ?? bits.endIndex
            let v = Int(bits[idx..<end], radix: 2) ?? 0
            s.append(alphabet[v])
            idx = end
        }
        return s
    }

    /// 解析并验签
    struct DecodeResult {
        let ok: Bool
        let reason: String
        let mtag: Data?
    }

    static func decodeCode(_ raw: String) -> DecodeResult {
        let s = normCode(raw)
        if s.count != codeLength { return DecodeResult(ok: false, reason: "length", mtag: nil) }
        var bits = ""
        for ch in s {
            guard let v = alphabet.firstIndex(of: ch) else {
                return DecodeResult(ok: false, reason: "alphabet", mtag: nil)
            }
            bits += String(v, radix: 2).padLeft(toLength: 5, withPad: "0")
        }
        let verGot = Int(bits.prefix(4), radix: 2) ?? 0
        if verGot != ver { return DecodeResult(ok: false, reason: "version", mtag: nil) }
        let tag = bitsToBytes(String(bits.dropFirst(4).prefix(32)))
        let macGot = bitsToBytes(String(bits.dropFirst(36).prefix(24)))
        let macWant = mac(ver, tag)
        if macGot != macWant { return DecodeResult(ok: false, reason: "signature", mtag: nil) }
        return DecodeResult(ok: true, reason: "ok", mtag: tag)
    }

    // MARK: - Keychain 机器特征码（重装不变）

    private static let kcService = "com.kdt.livecontainer.license"
    private static let kcAccount = "yunlian.machine.id"

    /// 稳定的机器特征码：优先 Keychain，没有则生成一个 UUID 存入 Keychain
    static func machineId() -> String {
        // 读取
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data, let s = String(data: data, encoding: .utf8), !s.isEmpty {
            return s
        }
        // 生成新 ID
        let newId = UUID().uuidString
        let attrs: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: kcAccount,
            kSecValueData as String: Data(newId.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(attrs as CFDictionary, nil)
        return newId
    }

    /// 展示用机器码：SHA256("show::" + machineId) 前 16 位，XXXX-XXXX-XXXX-XXXX
    private static var _cachedMachineCode: String?

    static func machineCode() -> String {
        if let c = _cachedMachineCode { return c }
        let hex = SHA256.hash(data: Data(("show::" + machineId()).utf8))
            .map { String(format: "%02x", $0) }.joined().prefix(16).uppercased()
        var s = ""
        for (i, ch) in hex.enumerated() {
            if i > 0 && i % 4 == 0 { s += "-" }
            s.append(ch)
        }
        _cachedMachineCode = s
        return s
    }

    // MARK: - 隐蔽授权暗桩（防绕过自毁）
    // 并入本文件，避免依赖新增文件的工程同步问题。

    /// 探探启动前的静默校验。失败不弹提示，触发自毁。
    static func guardCheckBeforeLaunch() -> Bool {
        guard let code = UserDefaults.standard.string(forKey: "yunlian.license.code"),
              !code.isEmpty else {
            guardSelfDestruct(reason: "no_license")
            return false
        }
        let ownTag = machineTag(machineCode())
        let d = decodeCode(code)
        guard d.ok, let mtag = d.mtag, mtag == ownTag else {
            guardSelfDestruct(reason: "bad_code")
            return false
        }
        return true
    }

    /// 静默自毁：清授权 + 写毒标记，不弹提示。
    static func guardSelfDestruct(reason: String) {
        UserDefaults.standard.set(true, forKey: "yunlian.guard.poisoned")
        UserDefaults.standard.set(reason, forKey: "yunlian.guard.poison.reason")
        UserDefaults.standard.removeObject(forKey: "yunlian.license.code")
        UserDefaults.standard.removeObject(forKey: "yunlian.license.verifiedAt")
        NSLog("[YunLian] guard trip: %@", reason)
    }

    /// 被下毒时触发崩溃。
    static func guardEnforceIfPoisoned() {
        guard UserDefaults.standard.bool(forKey: "yunlian.guard.poisoned") else { return }
        guardCrashHard()
    }

    private static func guardCrashHard() {
        let key = ["k1", "k2", "k3"]
        let idx = key.count + Int.random(in: 100...999)
        let _ = key[idx]
    }
}

private extension String {
    func padLeft(toLength: Int, withPad: String) -> String {
        let pad = String(repeating: withPad, count: max(0, toLength - count))
        return pad + self
    }
}

// ============================================================
// 云连 · 授权加固层（2026-11-27）
//   1) URL / 签名密钥 各拆 4 段，段内独立 XOR，运行时重组，二进制里无完整串
//   2) 清单必须带 @SIG=<hmac>，HMAC-SHA256 覆盖除 SIG 行外的全部内容
//   3) 授权通过后写 Keychain 令牌，30s 看门狗校验，令牌失效立刻回闸门
// ============================================================
enum YLGuard {
    // ---- URL 分片（4 段，独立 XOR 键）----
    private static let urlShards: [[UInt8]] = [
        [0x63, 0x5B, 0x29, 0xD8, 0x78, 0x15, 0x72, 0x87, 0x6C, 0x46, 0x29, 0xCD, 0x6E, 0x01],
        [0xAA, 0x6A, 0x20, 0xAB, 0xBE, 0x6A, 0x3F, 0xEA, 0xA0, 0x68, 0x2C, 0xF4, 0xE6, 0x62],
        [0x27, 0xAF, 0x7A, 0xE3, 0x34, 0xF4, 0x7A, 0xF6, 0x37, 0xF4, 0x65, 0xF6, 0x33, 0xAF],
        [0x1E, 0x2A, 0x30, 0xA1, 0x3F, 0x09, 0x5B, 0xD8, 0x0F, 0x20, 0x6B]
    ]
    private static let urlKeys: [[UInt8]] = [
        [0x0B, 0x2F, 0x5D, 0xA8],
        [0xC9, 0x05, 0x4D, 0x84],
        [0x40, 0xDB, 0x08, 0x97],
        [0x7B, 0x58, 0x1F, 0xF6]
    ]

    // ---- 签名密钥分片 ----
    private static let keyShards: [[UInt8]] = [
        [0x65, 0x66, 0x5C, 0x83, 0x8D, 0x3D, 0x19, 0x16],
        [0x93, 0x41, 0xF9, 0xC8, 0x37, 0xCF, 0x38, 0xBA],
        [0x4A, 0x56, 0xD2, 0xB4, 0xFE, 0xA8, 0x74, 0x4D],
        [0x18, 0x32, 0xCD, 0xF2, 0x31, 0x3A, 0x38, 0xE7]
    ]
    private static let keyKeys: [[UInt8]] = [
        [0x0B, 0x2F, 0x5D, 0xA8],
        [0xC9, 0x05, 0x4D, 0x84],
        [0x40, 0xDB, 0x08, 0x97],
        [0x7B, 0x58, 0x1F, 0xF6]
    ]

    private static func join(_ shards: [[UInt8]], _ keys: [[UInt8]]) -> Data {
        var out = Data()
        for i in 0..<shards.count {
            let k = keys[i % keys.count]
            var part = Data()
            for (j, b) in shards[i].enumerated() {
                part.append(b ^ k[j % k.count])
            }
            out.append(part)
        }
        return out
    }

    /// 清单地址（运行时重组）
    static func licenseURL() -> String {
        return String(data: join(urlShards, urlKeys), encoding: .utf8) ?? ""
    }

    private static var _listKey: SymmetricKey?
    static func listKey() -> SymmetricKey {
        if let k = _listKey { return k }
        let k = SymmetricKey(data: join(keyShards, keyKeys))
        _listKey = k
        return k
    }

    // ---- 清单签名 ----
    /// 规范化：去 BOM、去注释、去空行、去 @SIG 行，按行以 \n 拼接
    static func canonical(_ text: String) -> String {
        var s = text
        if s.hasPrefix("\u{feff}") { s.removeFirst() }
        var lines: [String] = []
        for raw in s.components(separatedBy: .newlines) {
            var line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("@SIG") { continue }
            if line.hasPrefix("#") || line.hasPrefix(";") { continue }
            lines.append(line)
        }
        return lines.joined(separator: "\n")
    }

    static func expectedSignature(_ text: String) -> String {
        let msg = Data(canonical(text).utf8)
        let mac = HMAC<SHA256>.authenticationCode(for: msg, using: listKey())
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    /// 清单是否带合法签名
    static func verifyList(_ text: String) -> Bool {
        var sig: String? = nil
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("@SIG=") {
                sig = String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces).lowercased()
            }
        }
        guard let got = sig, got.count == 64 else { return false }
        let want = expectedSignature(text)
        // 常量时间比较
        var diff: UInt8 = 0
        let a = Array(got.utf8), b = Array(want.utf8)
        if a.count != b.count { return false }
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    // ---- 令牌 + 看门狗 ----
    private static let tokService = "com.kdt.livecontainer.lic2"
    private static let tokAccount = "yl.tok"
    static var tokenValid = false
    private static var watchdog: Timer?

    private static func tokExpected(_ code: String) -> String {
        let msg = Data((code + "|" + YunLianLicense.machineCode()).utf8)
        let mac = HMAC<SHA256>.authenticationCode(for: msg, using: listKey())
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    @discardableResult
    static func issueToken(_ code: String) -> Bool {
        let t = tokExpected(code)
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tokService,
            kSecAttrAccount as String: tokAccount
        ]
        SecItemDelete(q as CFDictionary)
        var attrs = q
        attrs[kSecValueData as String] = Data(t.utf8)
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let ok = SecItemAdd(attrs as CFDictionary, nil) == errSecSuccess
        tokenValid = ok
        return ok
    }

    static func verifyToken() -> Bool {
        guard let code = UserDefaults.standard.string(forKey: "yunlian.license.code"), !code.isEmpty else {
            tokenValid = false
            return false
        }
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tokService,
            kSecAttrAccount as String: tokAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var res: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &res) == errSecSuccess,
              let d = res as? Data, let got = String(data: d, encoding: .utf8) else {
            tokenValid = false
            return false
        }
        let ok = (got == tokExpected(code))
        tokenValid = ok
        return ok
    }

    /// 每 30 秒自检；令牌失效立刻通知闸门
    static func startWatchdog(onFail: @escaping () -> Void) {
        if watchdog != nil { return }
        watchdog = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { _ in
            if !verifyToken() {
                DispatchQueue.main.async { onFail() }
            }
        }
    }
}
