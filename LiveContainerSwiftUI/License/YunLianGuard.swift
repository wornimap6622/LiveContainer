//
//  YunLianGuard.swift
//  云连 · 隐蔽授权校验（防绕过暗桩）
//
//  设计要点：
//    - 所有校验静默进行，失败不弹任何提示（提示=给破解者定位线索）
//    - 校验失败让探探「启动后闪退」，而非优雅提示
//    - 校验点散落在启动探探、App 启动等多个关键路径
//

import Foundation
import CryptoKit

enum YunLianGuard {
    // MARK: - 校验入口

    /// 探探启动前的静默校验。
    /// 返回 true = 放行；false = 已触发自毁（探探会闪退），不弹提示。
    static func checkBeforeLaunch() -> Bool {
        // 1. 授权状态：必须有已激活的码
        guard let code = UserDefaults.standard.string(forKey: "yunlian.license.code"),
              !code.isEmpty else {
            selfDestruct(reason: "no_license")
            return false
        }
        // 2. 验签 + 机器绑定（离线即可判，不依赖网络）
        let ownTag = YunLianLicense.machineTag(YunLianLicense.machineCode())
        let d = YunLianLicense.decodeCode(code)
        guard d.ok, let mtag = d.mtag, mtag == ownTag else {
            selfDestruct(reason: "bad_code")
            return false
        }
        return true
    }

    // MARK: - 隐蔽自毁

    /// 静默自毁：清理授权 + 写毒标记。不弹提示。
    static func selfDestruct(reason: String) {
        UserDefaults.standard.set(true, forKey: "yunlian.guard.poisoned")
        UserDefaults.standard.set(reason, forKey: "yunlian.guard.poison.reason")
        UserDefaults.standard.removeObject(forKey: "yunlian.license.code")
        UserDefaults.standard.removeObject(forKey: "yunlian.license.verifiedAt")
        NSLog("[YunLian] guard trip: %@", reason)
    }

    /// 探探启动时调用：如果被下毒，触发崩溃（而非正常启动）
    static func enforceIfPoisoned() {
        guard UserDefaults.standard.bool(forKey: "yunlian.guard.poisoned") else {
            return
        }
        // 触发确定性的崩溃
        crashHard()
    }

    private static func crashHard() {
        // 可靠的崩溃方式：强制解包一个 nil 可选值，产生 SIGTRAP
        // 用不易被静态识别的形式
        let key = ["k1", "k2", "k3"]
        let idx = key.count + Int.random(in: 100...999)
        let _ = key[idx]
    }
}
