//
//  LCContainerView.swift
//  LiveContainerSwiftUI
//
//  Created by s s on 2024/12/6.
//

import SwiftUI

protocol LCContainerViewDelegate {
    func unbindContainer(container: LCContainer)
    func setDefaultContainer(container: LCContainer)
    func saveContainer(container: LCContainer)
    
    func getSettingsBundle() -> Bundle?
    func getContainerURL(container: LCContainer) -> URL
    func getBundleId() -> String
}

// 伪造机型列表（machine 标识 -> 显示名）
private let SPOOF_MODELS: [(machine: String, name: String)] = [
    ("", "随机机型"),
    ("iPhone12,1", "iPhone 11"),
    ("iPhone12,3", "iPhone 11 Pro"),
    ("iPhone12,5", "iPhone 11 Pro Max"),
    ("iPhone12,8", "iPhone SE (2nd)"),
    ("iPhone13,1", "iPhone 12 mini"),
    ("iPhone13,2", "iPhone 12"),
    ("iPhone13,3", "iPhone 12 Pro"),
    ("iPhone13,4", "iPhone 12 Pro Max"),
    ("iPhone14,4", "iPhone 13 mini"),
    ("iPhone14,5", "iPhone 13"),
    ("iPhone14,7", "iPhone 14"),
    ("iPhone14,8", "iPhone 14 Plus"),
    ("iPhone14,2", "iPhone 13 Pro"),
    ("iPhone14,3", "iPhone 13 Pro Max"),
    ("iPhone15,2", "iPhone 14 Pro"),
    ("iPhone15,3", "iPhone 14 Pro Max"),
    ("iPhone15,4", "iPhone 15"),
    ("iPhone15,5", "iPhone 15 Plus"),
    ("iPhone16,1", "iPhone 15 Pro"),
    ("iPhone16,2", "iPhone 15 Pro Max"),
    ("iPhone17,1", "iPhone 16 Pro"),
    ("iPhone17,2", "iPhone 16 Pro Max"),
    ("iPhone17,3", "iPhone 16"),
    ("iPhone17,4", "iPhone 16 Plus"),
    ("iPhone18,1", "iPhone 17 Pro"),
    ("iPhone18,2", "iPhone 17 Pro Max"),
    ("iPhone18,3", "iPhone 17"),
    ("iPhone18,4", "iPhone Air"),
    ("iPhone19,3", "iPhone 18 Pro"),
    ("iPhone19,4", "iPhone 18 Pro Max"),
]

struct LCContainerView : View {
    @ObservedObject var container : LCContainer
    let delegate : LCContainerViewDelegate
    @Binding var uiDefaultDataFolder : String?
    @State var settingsBundle : Bundle? = nil
    
    @StateObject private var removeContainerAlert = YesNoHelper()
    @StateObject private var deleteDataAlert = YesNoHelper()
    @StateObject private var removeKeychainAlert = YesNoHelper()
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var sharedModel : SharedModel
    @State private var typingContainerName : String = ""
    @State private var typingIDFV: String = ""
    @State private var inUse = false
    @State private var runningLC : String? = nil
    
    @State private var errorShow = false
    @State private var errorInfo = ""
    @State private var successShow = false
    @State private var successInfo = ""
    
    init(container: LCContainer, uiDefaultDataFolder : Binding<String?>, delegate: LCContainerViewDelegate) {
        self._container = ObservedObject(initialValue: container)
        self.delegate = delegate
        self._typingContainerName = State(initialValue: container.name)
        self._uiDefaultDataFolder = Binding(projectedValue: uiDefaultDataFolder)
    }
    
    var body: some View {
        Form {
            if !(container.storageBookMark != nil && container.resolvedContainerURL == nil) {
                
                Section {
                    HStack {
                        Text("lc.container.containerName".loc)
                        Spacer()
                        TextField("lc.container.containerName".loc, text: $typingContainerName)
                            .multilineTextAlignment(.trailing)
                            .onSubmit {
                                container.name = typingContainerName
                                saveContainer()
                            }
                    }
                    HStack {
                        Text("lc.container.containerFolderName".loc)
                        Spacer()
                        Text(container.folderName)
                            .foregroundStyle(.gray)
                    }
                    Toggle(isOn: $container.isolateAppGroup) {
                        Text("lc.container.isolateAppGroup".loc)
                    }
                    .onChange(of: container.isolateAppGroup) { newValue in
                        saveContainer()
                    }
                    
                    if let settingsBundle {
                        NavigationLink {
                            AppPreferenceView(bundleId: delegate.getBundleId(), settingsBundle: settingsBundle, containerURL: delegate.getContainerURL(container: container))
                        } label: {
                            Text("lc.container.preferences".loc)
                        }
                    }
                    if container.folderName == uiDefaultDataFolder {
                        Text("lc.container.alreadyDefaultContainer".loc)
                            .foregroundStyle(.gray)
                    } else {
                        Button {
                            setAsDefault()
                        } label: {
                            Text("lc.container.setDefaultContainer".loc)
                        }
                    }
                } footer: {
                    Text("lc.container.defaultContainerDesc".loc)
                }
                
                Section {
                    Toggle(isOn: $container.spoofIdentifierForVendor) {
                        Text("lc.container.spoofIdentifierForVendor".loc)
                    }
                    .onChange(of: container.spoofIdentifierForVendor) { newValue in
                        saveContainer()
                    }
                    
                    if container.spoofIdentifierForVendor {
                        HStack {
                            Text("UUID")
                            TextField("lc.common.auto".loc, text: $typingIDFV)
                                .multilineTextAlignment(.trailing)
                                .onSubmit {
                                    saveIDFV()
                                }
                        }
                    }
                    
                    Picker(selection: $container.spoofModel) {
                        ForEach(SPOOF_MODELS, id: \.machine) { m in
                            Text(m.name).tag(m.machine)
                        }
                    } label: {
                        Text("伪造机型")
                    }
                    .onChange(of: container.spoofModel) { newValue in
                        saveModel()
                    }
                }

                Section {
                    Toggle(isOn: $container.spoofLocationEnabled) {
                        Text("伪装定位")
                    }
                    .onChange(of: container.spoofLocationEnabled) { _ in
                        saveContainer()
                    }
                    if container.spoofLocationEnabled {
                        NavigationLink {
                            LCLocationPickerView(latitude: $container.spoofLatitude,
                                                 longitude: $container.spoofLongitude) {
                                saveContainer()
                            }
                        } label: {
                            HStack {
                                Text("选择位置")
                                Spacer()
                                Text(locationSummary).foregroundStyle(.gray)
                            }
                        }
                    }
                } footer: {
                    Text("开启后，容器内 App 读到的定位为本机所选坐标")
                }

                Section {
                    if inUse {
                        Text("lc.container.inUse".loc)
                            .foregroundStyle(.gray)
                        
                    } else {
                        if !container.isShared || container.storageBookMark != nil {
                            Button {
                                openDataFolder()
                            } label: {
                                Text("lc.appBanner.openDataFolder".loc)
                            }
                            Button {
                                unbindContainer()
                            } label: {
                                Text("lc.container.unbind".loc)
                            }
                        }
                        Button(role:.destructive) {
                            Task { await deleteData() }
                        } label: {
                            Text("lc.container.deleteData".loc)
                        }
                        
                        Button(role:.destructive) {
                            Task { await cleanUpKeychain() }
                        } label: {
                            Text("lc.settings.cleanKeychain".loc)
                        }
                        
                        if(container.storageBookMark == nil) {
                            Button(role:.destructive) {
                                Task { await removeContainer() }
                            } label: {
                                Text("lc.container.removeContainer".loc)
                            }
                        }
                        
                    }
                }
            } else {
                Section {
                    if container.bookmarkResolved {
                        Text("lc.container.externalStorageUnavailable".loc)
                    } else {
                        Text("lc.container.bookmarkResolveInProgress".loc)
                    }

                }
                
                Section {
                    Button(role:.destructive) {
                        Task { await removeContainer() }
                    } label: {
                        Text("lc.container.removeContainer".loc)
                    }
                }
            }
        }
        .navigationTitle(container.name)
        .navigationBarTitleDisplayMode(.inline)
        .alert("lc.common.error".loc, isPresented: $errorShow){
        } message: {
            Text(errorInfo)
        }
        .alert("lc.common.success".loc, isPresented: $successShow){
        } message: {
            Text(successInfo)
        }
        
        .alert("lc.container.removeContainer".loc, isPresented: $removeContainerAlert.show) {
            Button(role: .destructive) {
                removeContainerAlert.close(result: true)
            } label: {
                Text("lc.common.delete".loc)
            }
            Button("lc.common.cancel".loc, role: .cancel) {
                removeContainerAlert.close(result: false)
            }
        } message: {
            Text("lc.container.removeContainerDesc".loc)
        }
        
        .alert("lc.container.deleteData".loc, isPresented: $deleteDataAlert.show) {
            Button(role: .destructive) {
                deleteDataAlert.close(result: true)
            } label: {
                Text("lc.common.delete".loc)
            }
            Button("lc.common.cancel".loc, role: .cancel) {
                deleteDataAlert.close(result: false)
            }
        } message: {
            Text("lc.container.deleteDataDesc".loc)
        }
        
        .alert("lc.settings.cleanKeychain".loc, isPresented: $removeKeychainAlert.show) {
            Button(role: .destructive) {
                removeKeychainAlert.close(result: true)
            } label: {
                Text("lc.common.delete".loc)
            }
            Button("lc.common.cancel".loc, role: .cancel) {
                removeKeychainAlert.close(result: false)
            }
        } message: {
            Text("lc.container.removeKeychainDesc".loc)
        }
        .onAppear() {
            container.reloadInfoPlist()
            if let spoofedIDFV = container.spoofedIdentifier {
                typingIDFV = spoofedIDFV
            }
            settingsBundle = delegate.getSettingsBundle()
            runningLC = LCSharedUtils.getContainerUsingLCScheme(withFolderName: container.folderName)
            inUse = runningLC != nil
        }
        
    }
    
    var locationSummary: String {
        if container.spoofLatitude == 0 && container.spoofLongitude == 0 {
            return "未选择"
        }
        return String(format: "%.5f, %.5f", container.spoofLatitude, container.spoofLongitude)
    }

    func saveIDFV() {
        guard let newIDFV = UUID(uuidString: typingIDFV) else {
            errorInfo = "lc.container.invalidIDFV".loc
            errorShow = true
            return
        }
        container.spoofedIdentifier = newIDFV.uuidString
        delegate.saveContainer(container: container)
    }

    func saveModel() {
        // 1. 写 .xh_spoof_model.txt 到容器 Documents，供 XHSpoof 读取
        let docDir = LCPath.dataPath.appendingPathComponent(container.folderName).appendingPathComponent("Documents")
        do {
            try FileManager.default.createDirectory(at: docDir, withIntermediateDirectories: true)
            let specPath = docDir.appendingPathComponent(".xh_spoof_model.txt")
            try container.spoofModel.write(to: specPath, atomically: true, encoding: .utf8)
            // 删除旧身份，强制下次启动按新机型重新生成
            let identPath = docDir.appendingPathComponent(".xh_spoof_identity.plist")
            if FileManager.default.fileExists(atPath: identPath.path) {
                try FileManager.default.removeItem(at: identPath)
            }
        } catch {
            // 容器目录不存在时忽略，下次启动探探前会再写
        }
        delegate.saveContainer(container: container)
    }

    func saveContainer() {
        if let usingLC = LCSharedUtils.getContainerUsingLCScheme(withFolderName: container.folderName) {
            errorInfo = "lc.container.inUseBy %@".localizeWithFormat(usingLC)
            errorShow = true
            return
        }
        
        delegate.saveContainer(container: container)
    }
    
    func openDataFolder() {
        let url = URL(string:"shareddocuments://\(LCPath.dataPath.path)/\(container.folderName)")
        UIApplication.shared.open(url!)
    }
    
    func setAsDefault() {
        delegate.setDefaultContainer(container: container)
    }
    
    func removeContainer() async {
        if let usingLC = LCSharedUtils.getContainerUsingLCScheme(withFolderName: container.folderName) {
            errorInfo = "lc.container.inUseBy %@".localizeWithFormat(usingLC)
            errorShow = true
            return
        }
        guard let ans = await removeContainerAlert.open(), ans else {
            return
        }
        do {
            let fm = FileManager.default
            try fm.removeItem(at: container.containerURL)
        } catch {
            errorInfo = error.localizedDescription
            errorShow = true
            return
        }
        
        dismiss()
        delegate.unbindContainer(container: container)
    }
    
    func unbindContainer() {
        if let usingLC = LCSharedUtils.getContainerUsingLCScheme(withFolderName: container.folderName) {
            errorInfo = "lc.container.inUseBy %@".localizeWithFormat(usingLC)
            errorShow = true
            return
        }
        
        dismiss()
        delegate.unbindContainer(container: container)
    }
    
    func cleanUpKeychain() async {
        if let usingLC = LCSharedUtils.getContainerUsingLCScheme(withFolderName: container.folderName) {
            errorInfo = "lc.container.inUseBy %@".localizeWithFormat(usingLC)
            errorShow = true
            return
        }
        guard let ans = await removeKeychainAlert.open(), ans else {
            return
        }
        
        LCUtils.removeAppKeychain(dataUUID: container.folderName)
    }
    
    func deleteData() async {
        if let usingLC = LCSharedUtils.getContainerUsingLCScheme(withFolderName: container.folderName) {
            errorInfo = "lc.container.inUseBy %@".localizeWithFormat(usingLC)
            errorShow = true
            return
        }
        guard let ans = await deleteDataAlert.open(), ans else {
            return
        }
        do {
            let fm = FileManager.default
            for file in try fm.contentsOfDirectory(at: container.containerURL, includingPropertiesForKeys: nil) {
                if file.lastPathComponent == "LCContainerInfo.plist" {
                    continue
                }
                try fm.removeItem(at: file)
            }
        } catch {
            errorInfo = error.localizedDescription
            errorShow = true
        }
    }
}


// MARK: - 定位选点（地图搜索 + 长按选点）
import MapKit

struct LCLocationPickerView: View {
    @Binding var latitude: Double
    @Binding var longitude: Double
    var onDone: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var query: String = ""
    @State private var pin: CLLocationCoordinate2D
    @State private var region: MKCoordinateRegion
    @State private var searching = false

    init(latitude: Binding<Double>, longitude: Binding<Double>, onDone: @escaping () -> Void) {
        self._latitude = latitude
        self._longitude = longitude
        self.onDone = onDone
        let lat = latitude.wrappedValue == 0 ? 39.9042 : latitude.wrappedValue
        let lon = longitude.wrappedValue == 0 ? 116.4074 : longitude.wrappedValue
        let c = CLLocationCoordinate2D(latitude: lat, longitude: lon)
        self._pin = State(initialValue: c)
        self._region = State(initialValue: MKCoordinateRegion(center: c,
            span: MKCoordinateSpan(latitudeDelta: 0.05, longitudeDelta: 0.05)))
    }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                HStack {
                    TextField("搜索地点", text: $query)
                        .textFieldStyle(.roundedBorder)
                    Button("搜索") { search() }
                        .disabled(query.isEmpty || searching)
                }
                .padding()

                LCLongPressMap(pin: $pin, region: $region)
                    .ignoresSafeArea(edges: .bottom)

                HStack {
                    Text(String(format: "%.5f, %.5f", pin.latitude, pin.longitude))
                        .font(.footnote).foregroundStyle(.secondary)
                    Spacer()
                    Button("保存") {
                        latitude = pin.latitude
                        longitude = pin.longitude
                        onDone()
                        dismiss()
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding()
            }
            .navigationTitle("选择位置")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("取消") { dismiss() }
                }
            }
        }
    }

    private func search() {
        searching = true
        let req = MKLocalSearch.Request()
        req.naturalLanguageQuery = query
        MKLocalSearch(request: req).start { resp, _ in
            searching = false
            guard let item = resp?.mapItems.first else { return }
            let c = item.placemark.coordinate
            pin = c
            region = MKCoordinateRegion(center: c,
                span: MKCoordinateSpan(latitudeDelta: 0.02, longitudeDelta: 0.02))
        }
    }
}

struct LCLongPressMap: UIViewRepresentable {
    @Binding var pin: CLLocationCoordinate2D
    @Binding var region: MKCoordinateRegion

    func makeUIView(context: Context) -> MKMapView {
        let mv = MKMapView()
        mv.delegate = context.coordinator
        mv.setRegion(region, animated: false)
        let lp = UILongPressGestureRecognizer(target: context.coordinator,
                                              action: #selector(Coordinator.onLongPress(_:)))
        mv.addGestureRecognizer(lp)
        return mv
    }

    func updateUIView(_ uiView: MKMapView, context: Context) {
        if uiView.region.center.latitude != region.center.latitude ||
            uiView.region.center.longitude != region.center.longitude {
            uiView.setRegion(region, animated: true)
        }
        uiView.removeAnnotations(uiView.annotations)
        let a = MKPointAnnotation()
        a.coordinate = pin
        uiView.addAnnotation(a)
    }

    func makeCoordinator() -> Coordinator { Coordinator(self) }

    final class Coordinator: NSObject, MKMapViewDelegate {
        var parent: LCLongPressMap
        init(_ p: LCLongPressMap) { parent = p }

        @objc func onLongPress(_ g: UILongPressGestureRecognizer) {
            guard g.state == .began, let mv = g.view as? MKMapView else { return }
            let pt = g.location(in: mv)
            parent.pin = mv.convert(pt, toCoordinateFrom: mv)
        }
    }
}
