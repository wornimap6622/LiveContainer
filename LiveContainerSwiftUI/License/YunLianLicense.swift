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

    // MARK: - 机器特征码（固定，不随签名/容器变化）

    private static let kcService = "com.kdt.livecontainer.license"
    private static let kcAccount = "yunlian.machine.id"
    private static let kcCodeAccount = "yunlian.license.code"

    /// 机器 ID（一机一码）。
    ///
    /// 取值顺序，任何一步失败都不会让机器码漂移：
    ///   1) Keychain 里已存的随机 UUID（首次启动写入，重装/换容器/重签名都保留）
    ///   2) 读不到且确实是 errSecItemNotFound → 生成一个并写入
    ///   3) Keychain 写失败（少见）→ 退回用 IDFV 派生，保证仍然是"这台机器"的稳定值
    ///
    /// 关键点：只有 errSecItemNotFound 才允许生成新值。
    /// errSecInteractionNotAllowed（重启后首次解锁前）等其它错误一律不写不删，
    /// 否则会像旧实现那样把已发出的激活码全部作废。
    private static var _cachedMachineId: String?

    private static func readMachineIdKC() -> String? {
        var q = kcQuery(account: kcAccount)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecSuccess,
           let d = out as? Data,
           let v = String(data: d, encoding: .utf8),
           !v.isEmpty {
            return v
        }
        return nil
    }

    /// 返回 nil 表示"确定不存在"，可以安全生成；返回 false 表示写失败。
    private static func readMachineIdStatus() -> OSStatus {
        var q = kcQuery(account: kcAccount)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        return SecItemCopyMatching(q as CFDictionary, &out)
    }

    @discardableResult
    private static func writeMachineIdKC(_ v: String) -> Bool {
        var attrs = kcQuery(account: kcAccount)
        attrs[kSecValueData as String] = Data(v.utf8)
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let st = SecItemAdd(attrs as CFDictionary, nil)
        if st == errSecDuplicateItem {
            // 已存在就更新，不删了再写（避免中间态丢码）
            let q = kcQuery(account: kcAccount)
            let upd = [kSecValueData as String: Data(v.utf8)] as [String: Any]
            return SecItemUpdate(q as CFDictionary, upd as CFDictionary) == errSecSuccess
        }
        return st == errSecSuccess
    }

    static func machineId() -> String {
        if let c = _cachedMachineId { return c }

        // 1) 已存在
        if let saved = readMachineIdKC() {
            _cachedMachineId = saved
            return saved
        }

        // 2) 只有"确定不存在"才生成
        let st = readMachineIdStatus()
        if st == errSecItemNotFound {
            let fresh = UUID().uuidString
            if writeMachineIdKC(fresh) {
                _cachedMachineId = fresh
                return fresh
            }
        }

        // 3) 兜底：Keychain 不可用（交互锁定 / 写失败）时用 IDFV 派生。
        //    IDFV 在 bundle id 不变时跨重签名、跨重装都稳定，仍是"这台机器"的值。
        let idfv = UIDevice.current.identifierForVendor?.uuidString ?? "no-idfv"
        let seed = "YL-IDFV::" + idfv + "::" + (Bundle.main.bundleIdentifier ?? "")
        let hex = SHA256.hash(data: Data(seed.utf8)).map { String(format: "%02x", $0) }.joined()
        let derived = "YL-IDFV-" + String(hex.prefix(24)).uppercased()
        _cachedMachineId = derived
        return derived
    }

    // MARK: - 激活码持久化（Keychain，容器重建不丢）

    private static func kcQuery(account: String) -> [String: Any] {
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: kcService,
            kSecAttrAccount as String: account
        ]
    }

    /// 读取已激活的码：Keychain 优先，其次兼容旧版 UserDefaults 并自动迁移。
    static func loadStoredCode() -> String? {
        var q = kcQuery(account: kcCodeAccount)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        if SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
           let d = out as? Data,
           let s = String(data: d, encoding: .utf8),
           !s.isEmpty {
            return s
        }
        if let old = UserDefaults.standard.string(forKey: "yunlian.license.code"), !old.isEmpty {
            saveStoredCode(old)
            return old
        }
        return nil
    }

    static func saveStoredCode(_ code: String) {
        guard !code.isEmpty else { return }
        SecItemDelete(kcQuery(account: kcCodeAccount) as CFDictionary)
        var attrs = kcQuery(account: kcCodeAccount)
        attrs[kSecValueData as String] = Data(code.utf8)
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(attrs as CFDictionary, nil)
    }

    static func clearStoredCode() {
        SecItemDelete(kcQuery(account: kcCodeAccount) as CFDictionary)
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
        guard let code = loadStoredCode(),
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
        clearStoredCode()
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
