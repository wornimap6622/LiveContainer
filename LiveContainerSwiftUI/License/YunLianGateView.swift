//
//  YunLianGateView.swift
//  云连 · 授权门闩（对应无敌抢单 gate.js）
//
//  启动时先校验授权：通过则显示主界面，否则只显示激活页。
//

import SwiftUI

struct YunLianGateView: View {
    @StateObject private var license = YunLianLicenseService.shared

    var body: some View {
        Group {
            switch license.state {
            case .authorized:
                LCTabView()
                    .preferredColorScheme(.dark)
                    .tint(Color(red: 0.0, green: 0.941, blue: 1.0))
                    .environmentObject(DataManager.shared.model)
                    .environmentObject(LCAppSortManager.shared)
            case .needsActivation(let reason):
                YunLianActivationView(reason: reason)
            case .checking:
                ZStack {
                    LinearGradient(
                        colors: [Color(red: 0.04, green: 0.03, blue: 0.09),
                                 Color(red: 0.02, green: 0.06, blue: 0.12)],
                        startPoint: .topLeading, endPoint: .bottomTrailing
                    )
                    .ignoresSafeArea()
                    ProgressView()
                        .tint(Color(red: 0.0, green: 0.941, blue: 1.0))
                }
            }
        }
        .task {
            await license.checkOnLaunch()
        }
    }
}
