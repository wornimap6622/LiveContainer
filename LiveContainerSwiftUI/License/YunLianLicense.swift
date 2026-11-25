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
    private static var _cachedMachineId: String?

    static func machineId() -> String {
        if let cached = _cachedMachineId { return cached }
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
            _cachedMachineId = s
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
        _cachedMachineId = newId
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
}

private extension String {
    func padLeft(toLength: Int, withPad: String) -> String {
        let pad = String(repeating: withPad, count: max(0, toLength - count))
        return pad + self
    }
}
