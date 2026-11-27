//
//  YunLianLicenseService.swift
//  云连 · 授权校验服务（对应无敌抢单 guard_src/core.js 的清单校验部分）
//
//  清单格式：每行 `激活码=1|0`，`@STRICT=1` 控制严格模式。
//  严格模式：卡密必须在清单里且为 1 才放行；非严格模式：签名+机器绑定即放行。
//

import Foundation
import CryptoKit

@MainActor
final class YunLianLicenseService: ObservableObject {
    static let shared = YunLianLicenseService()

    @Published var state: YunLianAuthState = .checking

    /// 清单模式（严格 = 必须登记）
    static let strictList = true
    /// 网络超时
    private let netTimeout: TimeInterval = 5
    /// 清单缓存时长
    private let listTTL: TimeInterval = 90
    /// 离线宽限（在线校验失败后允许离线启动的时长）
    private let offlineGrace: TimeInterval = 12 * 3600

    private var listCache: (at: Date, map: [String: Bool])?
    private var refreshTimer: Timer?

    // MARK: - 清单拉取

    private func fetchList(force: Bool) async throws -> [String: Bool] {
        let now = Date()
        if !force, let c = listCache, now.timeIntervalSince(c.at) < listTTL {
            return c.map
        }
        let urlStr = YLGuard.licenseURL() + "?ts=" + String(Int(now.timeIntervalSince1970 * 1000))
        guard let url = URL(string: urlStr) else { throw YunLianAuthError.badURL }

        var req = URLRequest(url: url)
        req.timeoutInterval = netTimeout
        req.cachePolicy = .reloadIgnoringLocalCacheData
        req.setValue("text/plain,text/*,*/*", forHTTPHeaderField: "Accept")
        req.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        req.setValue("no-store", forHTTPHeaderField: "Cache-Control")

        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
            throw YunLianAuthError.network
        }
        let text = String(data: data, encoding: .utf8) ?? ""
        // 清单签名校验：无 @SIG 或验签失败一律视为无效清单
        guard YLGuard.verifyList(text) else { throw YunLianAuthError.badSignature }
        let map = parseList(text)
        guard !map.isEmpty else { throw YunLianAuthError.emptyList }
        listCache = (now, map)
        return map
    }

    /// 解析清单
    func parseList(_ text: String) -> [String: Bool] {
        var out: [String: Bool] = [:]
        var s = text
        if s.hasPrefix("\u{feff}") { s.removeFirst() }
        for rawLine in s.components(separatedBy: .newlines) {
            var line = rawLine
            if let r = line.range(of: "#") { line = String(line[..<r.lowerBound]) }
            if let r = line.range(of: ";") { line = String(line[..<r.lowerBound]) }
            line = line.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            // @KEY=1 形式
            if line.hasPrefix("@") {
                let body = line.dropFirst()
                let parts = body.components(separatedBy: CharacterSet(charactersIn: "=:："))
                if parts.count >= 2, let key = parts.first, let val = parts[1].trimmingCharacters(in: .whitespaces).first {
                    out["@" + key.uppercased()] = (val == "1")
                }
                continue
            }
            // 码=1 形式
            let parts = line.components(separatedBy: CharacterSet(charactersIn: "=:："))
            guard parts.count >= 2 else { continue }
            let code = YunLianLicense.normCode(parts[0])
            let val = parts[1].trimmingCharacters(in: .whitespaces).first
            let on = (val == "1")
            if code.count >= 4 {
                if out[code] == nil { out[code] = on }
                else if on { out[code] = true }
            }
        }
        return out
    }

    // MARK: - 决策

    func decide(code: String, ownTag: Data, map: [String: Bool]?, strict: Bool) -> (ok: Bool, reason: String) {
        let d = YunLianLicense.decodeCode(code)
        if !d.ok {
            return (false, d.reason == "signature" ? "bad_sig" : "format")
        }
        if let mtag = d.mtag {
            if mtag != ownTag { return (false, "other_machine") }
        }
        let isStrict = map?["@STRICT"] ?? strict
        if map == nil { return isStrict ? (false, "network") : (true, "ok") }
        let norm = YunLianLicense.normCode(code)
        if map?[norm] == false { return (false, "disabled") }
        if map?[norm] == nil && isStrict { return (false, "not_registered") }
        return (true, "ok")
    }

    // MARK: - 激活提交

    func submit(rawCode: String) async -> (ok: Bool, reason: String) {
        let code = YunLianLicense.normCode(rawCode)
        if code.isEmpty { return (false, "format") }

        var map: [String: Bool]?
        do { map = try await fetchList(force: true) }
        catch { map = nil }

        let ownTag = YunLianLicense.machineTag(YunLianLicense.machineCode())
        let r = decide(code: code, ownTag: ownTag, map: map, strict: Self.strictList)
        if r.ok {
            UserDefaults.standard.set(code, forKey: "yunlian.license.code")
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: "yunlian.license.verifiedAt")
            YLGuard.issueToken(code)
            state = .authorized
        }
        return r
    }

    // MARK: - 启动校验

    func checkOnLaunch(silent: Bool = false) async {
        if !silent { state = .checking }
        // 30 秒看门狗：令牌被清/被改 → 立刻回闸门
        YLGuard.startWatchdog { [weak self] in
            guard let self else { return }
            self.state = .needsActivation(reason: "token")
        }
        if refreshTimer == nil {
            refreshTimer = Timer.scheduledTimer(withTimeInterval: 1800, repeats: true) { [weak self] _ in
                Task { @MainActor in
                    guard let self else { return }
                    if case .authorized = self.state {
                        await self.checkOnLaunch(silent: true)
                    }
                }
            }
        }
        // 是否有已激活的码
        guard let code = UserDefaults.standard.string(forKey: "yunlian.license.code"),
              !code.isEmpty else {
            state = .needsActivation(reason: "no_session")
            return
        }

        // 本地令牌自检：令牌缺失/被篡改 → 直接回闸门（防清 UserDefaults 绕过）
        if !YLGuard.verifyToken() {
            state = .needsActivation(reason: "token")
            return
        }

        let ownTag = YunLianLicense.machineTag(YunLianLicense.machineCode())

        var map: [String: Bool]?
        var sigBad = false
        do { map = try await fetchList(force: false) }
        catch let e as YunLianAuthError {
            if case .badSignature = e { sigBad = true }
            map = nil
        }
        catch { map = nil }

        // 清单签名无效 = 有人改了清单 → 直接拒绝，不给离线宽限
        if sigBad {
            state = .needsActivation(reason: "signature")
            return
        }

        if map == nil {
            // 离线：宽限期内放行
            let vet = UserDefaults.standard.double(forKey: "yunlian.license.verifiedAt")
            if Date().timeIntervalSince1970 - vet <= offlineGrace {
                state = .authorized
            } else {
                state = .needsActivation(reason: "network")
            }
            return
        }

        let r = decide(code: code, ownTag: ownTag, map: map, strict: Self.strictList)
        if r.ok {
            UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: "yunlian.license.verifiedAt")
            state = .authorized
        } else {
            state = .needsActivation(reason: r.reason)
        }
    }
}

enum YunLianAuthError: Error {
    case badURL
    case network
    case emptyList
    case badSignature
}

enum YunLianAuthState {
    case checking
    case authorized
    case needsActivation(reason: String)
}
