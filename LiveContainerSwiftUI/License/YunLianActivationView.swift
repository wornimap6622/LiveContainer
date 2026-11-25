//
//  YunLianActivationView.swift
//  云连 · 激活界面（对应无敌抢单 act.html/act.js）
//

import SwiftUI

struct YunLianActivationView: View {
    @State private var code: String = ""
    @State private var message: String = ""
    @State private var isError: Bool = false
    @State private var busy: Bool = false
    @State private var machine: String = YunLianLicense.machineCode()

    let reason: String

    private let reasonText: [String: String] = [
        "no_session": "请输入本机专用激活码",
        "network": "无法连接授权服务器，请检查网络后重试",
        "format": "激活码格式不正确",
        "bad_sig": "激活码无效，请核对后重试",
        "other_machine": "此激活码绑定了其他设备",
        "not_registered": "该激活码尚未开通，请联系管理员登记",
        "disabled": "该激活码已被停用"
    ]

    var body: some View {
        ZStack {
            // 赛博背景：深色渐变
            LinearGradient(
                colors: [Color(red: 0.04, green: 0.03, blue: 0.09),
                         Color(red: 0.02, green: 0.06, blue: 0.12)],
                startPoint: .topLeading, endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 20) {
                // 标题
                VStack(spacing: 6) {
                    Text("云连")
                        .font(.system(size: 34, weight: .bold))
                        .foregroundColor(Color(red: 0.0, green: 0.94, blue: 1.0))
                    Text("授权激活")
                        .font(.system(size: 15))
                        .foregroundColor(Color(red: 0.0, green: 0.94, blue: 1.0).opacity(0.7))
                }
                .padding(.top, 40)

                // 机器码卡片
                VStack(alignment: .leading, spacing: 8) {
                    Text("本机特征码")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                    HStack {
                        Text(machine)
                            .font(.system(size: 16, weight: .medium, design: .monospaced))
                            .foregroundColor(.white)
                        Spacer()
                        Button {
                            UIPasteboard.general.string = machine
                        } label: {
                            Text("复制")
                                .font(.system(size: 12))
                                .foregroundColor(Color(red: 0.0, green: 0.94, blue: 1.0))
                        }
                    }
                    .padding(12)
                    .background(Color.white.opacity(0.06))
                    .cornerRadius(10)
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .stroke(Color(red: 0.0, green: 0.94, blue: 1.0).opacity(0.3), lineWidth: 1)
                    )
                    Text("把特征码发给管理员，换取本机专用激活码")
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                }
                .padding(.horizontal, 28)

                // 激活码输入
                VStack(alignment: .leading, spacing: 8) {
                    Text("激活码")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                    TextField("输入 12 位激活码", text: $code)
                        .font(.system(size: 16, design: .monospaced))
                        .textInputAutocapitalization(.characters)
                        .autocorrectionDisabled()
                        .padding(12)
                        .background(Color.white.opacity(0.06))
                        .cornerRadius(10)
                        .overlay(
                            RoundedRectangle(cornerRadius: 10)
                                .stroke(Color(red: 0.0, green: 0.94, blue: 1.0).opacity(0.3), lineWidth: 1)
                        )
                        .foregroundColor(.white)
                }
                .padding(.horizontal, 28)

                // 提示信息
                Text(message.isEmpty ? (reasonText[reason] ?? "请输入激活码") : message)
                    .font(.system(size: 12))
                    .foregroundColor(isError ? Color.red : Color.green)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 28)

                // 激活按钮
                Button {
                    Task { await doActivate() }
                } label: {
                    Text(busy ? "校验中…" : "立即激活")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.black)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Color(red: 0.0, green: 0.94, blue: 1.0))
                        .cornerRadius(12)
                        .shadow(color: Color(red: 0.0, green: 0.94, blue: 1.0).opacity(0.5), radius: 8)
                }
                .disabled(busy)
                .padding(.horizontal, 28)

                Spacer()
            }
        }
        .preferredColorScheme(.dark)
    }

    private func doActivate() async {
        busy = true
        let r = await YunLianLicenseService.shared.submit(rawCode: code)
        busy = false
        if r.ok {
            message = "授权成功，正在进入…"
            isError = false
        } else {
            message = reasonText[r.reason] ?? "激活失败，请重试"
            isError = true
        }
    }
}
