import SwiftUI
import UIKit
import MacDirtyCow

struct ContentView: View {
    
    @State private var kfd: UInt64 = 0
    
    @State private var puafPages = 2048
    @State private var puafMethod = 1
    @State private var kreadMethod = 1
    @State private var kwriteMethod = 1

    @State private var enableHideHomebar = false
    @State private var enableHideDock = false
    @State private var enableResSet = false
    @State private var enableReplacecert = true
    @State private var enableCustomSysColors = false
    @State private var changeRegion = false
    @State private var whitelist = false
    @State private var supervise = false
    @State private var enableCustomFont = false
    
    var puafPagesOptions = [16, 32, 64, 128, 256, 512, 1024, 2048]
    var puafMethodOptions = ["physpuppet", "smith"]
    var kreadMethodOptions = ["kqueue_workloop_ctl", "sem_open"]
    var kwriteMethodOptions = ["dup", "sem_open"]
    
    @State private var message = "ready!"
    
    @State private var isSettingsPopoverPresented = false // Track the visibility of the settings popup
    @State private var isTweaksPopoverPresented = false
    @State private var isFilePopoverPresented = false
    @State private var isJITPopoverPresented = false
    
    @State private var isLogPopoverPresented = false
    @State var advancedLogsTemporarilyEnabled: Bool = true
    @State var advancedLogsByDefault: Bool = true
    @Environment(\.presentationMode) var presentation
    
    func unsandboxing()  {
        do {
            try MacDirtyCow.unsandbox()
            DispatchQueue.main.async {
                message = "unsandboxed!"
            }
            if (MacDirtyCow.patch_installd() == true){
                DispatchQueue.main.async {
                    message = "patched installd!"
                }
            } else {
                DispatchQueue.main.async {
                    message = "error occur patching installd!"
                }
            }
        } catch {
            print(error)
        }
    }

    var body: some View {
        NavigationView {
            List {
                Section(header: Text("Status")) {
                    Text(message)
                    if kfd != 0 {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Success!")
                                .font(.headline)
                                .foregroundColor(.green)
                            Text("View output in Xcode")
                                .foregroundColor(.gray)
                        }
                    }
                }
                
                Section(header: Text("actions")) {
                    Text("kopen")
                        .onTapGesture{
                            kfd = do_kopen(UInt64(puafPages), UInt64(puafMethod), UInt64(kreadMethod), UInt64(kwriteMethod))
                            DispatchQueue.main.async {
                                message = "kopened!"
                            }
                        }.frame(minWidth: 0, maxWidth: .infinity, alignment: .leading).disabled(kfd != 0).foregroundColor(Color(red: 0.678, green: 0.847, blue: 0.901, opacity: 1))
                    Text("kclose")
                        .onTapGesture{
                            do_kclose()
                            puafPages = 0
                            kfd = 0
                            DispatchQueue.main.async {
                                message = "kclosed!"
                            }
                        }.frame(minWidth: 0, maxWidth: .infinity, alignment: .leading).disabled(kfd == 0).foregroundColor(Color(red: 0.678, green: 0.847, blue: 0.901, opacity: 1))
                    Text("fun and kclose")
                        .onTapGesture{
                            let tweaks = enabledTweaks()
                            var cTweaks: [UnsafeMutablePointer<CChar>?] = tweaks.map { strdup($0) }
                            cTweaks.append(nil)
                            cTweaks.withUnsafeMutableBufferPointer { buffer in
                                do_fun(buffer.baseAddress, Int32(buffer.count - 1))
                            }
                            cTweaks.forEach { free($0) }
                            DispatchQueue.main.async {
                                message = "done fun!"
                            }
                            usleep(1000)
                            do_kclose()
                            puafPages = 0
                            kfd = 0
                            DispatchQueue.main.async {
                                message = "kclose!"
                            }
                        }.frame(minWidth: 0, maxWidth: .infinity, alignment: .leading).disabled(kfd == 0).foregroundColor(Color(red: 0.678, green: 0.847, blue: 0.901, opacity: 1))
                    Text("do kfd tasks and kclose")
                        .onTapGesture{
                            do_tasks()
                            DispatchQueue.main.async {
                                message = "done!"
                            }
                            usleep(1000)
                            do_kclose()
                            puafPages = 0
                            kfd = 0
                            DispatchQueue.main.async {
                                message = "kclose!"
                            }
                        }.frame(minWidth: 0, maxWidth: .infinity, alignment: .leading).disabled(kfd == 0).foregroundColor(Color(red: 0.678, green: 0.847, blue: 0.901, opacity: 1))
                    Text("patch installd w/mdc")
                        .onTapGesture{
                            print("mdc")
                            unsandboxing()
                            DispatchQueue.main.async {
                                message = "sucecss!"
                            }
                        }.frame(minWidth: 0, maxWidth: .infinity, alignment: .leading).foregroundColor(Color(red: 0.678, green: 0.847, blue: 0.901, opacity: 1))
                    Text("kill backboardd")
                        .onTapGesture{
                            backboard_respring()
                            DispatchQueue.main.async {
                                message = "sucecss!"
                            }
                        }.frame(minWidth: 0, maxWidth: .infinity, alignment: .leading).foregroundColor(Color(red: 0.678, green: 0.847, blue: 0.901, opacity: 1))
                }
                
                Section(header: Text("Settings")) {
                    Button(action: {
                        isSettingsPopoverPresented.toggle()
                    }, label: {Text("Exploit Setting")}).foregroundColor(Color(red: 0.941, green: 0.502, blue: 0.502, opacity: 1))
                    Button(action: {
                        isTweaksPopoverPresented.toggle()
                    }, label: {Text("Tweak Setting")}).foregroundColor(Color(red: 0.941, green: 0.502, blue: 0.502, opacity: 1))
                }.buttonStyle(BorderlessButtonStyle())
                
                Section(header: Text("Tools")) {
                    Text("Dirty JIT")
                        .foregroundColor(Color(red: 0.941, green: 0.502, blue: 0.502, opacity: 1))
                        .onTapGesture {
                            isJITPopoverPresented.toggle()
                        }
                    Text("File Manager")
                        .foregroundColor(Color(red: 0.941, green: 0.502, blue: 0.502, opacity: 1))
                        .onTapGesture {
                            if (check_mdc()) {
                                do_tasks()
                            } else {
                                MacDirtyCow.unsandboxing()
                            }
                            isFilePopoverPresented.toggle()
                        }
                }
            }
            .accentColor(.green)
            .popover(isPresented: $isSettingsPopoverPresented, arrowEdge: .bottom) {
                settingsPopover
            }
            .popover(isPresented: $isTweaksPopoverPresented, arrowEdge: .bottom) {
                tweakSettings
            }
            .popover(isPresented: $isJITPopoverPresented, arrowEdge: .bottom) {
                DirtyJITView()
            }
            .popover(isPresented: $isFilePopoverPresented, arrowEdge: .bottom) {
                FileManagerUIKitViewControllerWrapper()
            }
        }
    }
    
    // Payload Settings Popover
    private var settingsPopover: some View {
        VStack {
            Section(header: Text("Payload Settings")) {
                Picker("puaf pages:", selection: $puafPages) {
                    ForEach(puafPagesOptions, id: \.self) { pages in
                        Text(String(pages))
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
                
                Picker("puaf method:", selection: $puafMethod) {
                    ForEach(0..<puafMethodOptions.count, id: \.self) { index in
                        Text(puafMethodOptions[index])
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
            }
            
            Section(header: Text("Kernel Settings")) {
                Picker("kread method:", selection: $kreadMethod) {
                    ForEach(0..<kreadMethodOptions.count, id: \.self) { index in
                        Text(kreadMethodOptions[index])
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
                
                Picker("kwrite method:", selection: $kwriteMethod) {
                    ForEach(0..<kwriteMethodOptions.count, id: \.self) { index in
                        Text(kwriteMethodOptions[index])
                    }
                }.pickerStyle(SegmentedPickerStyle())
                .disabled(kfd != 0)
            }
            
            Button("Apply Settings") {
                isSettingsPopoverPresented = false
            }
        }
        .padding()
    }

    private var tweakSettings: some View {
        VStack {
            // Hide Homebar
            Toggle(isOn: $enableHideHomebar) {
                HStack(spacing: 20) {
                    Image(systemName: enableHideHomebar ? "eye.slash.circle.fill" : "eye.circle")
                    .foregroundColor(.green)
                    .imageScale(.large)
                    Text("Hide Home Bar").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)

            // Hide Dock
            Toggle(isOn: $enableHideDock) {
                HStack(spacing: 20) {
                    Image(systemName: enableHideDock ? "eye.slash.circle.fill" : "eye.circle")
                        .foregroundColor(.green)
                        .imageScale(.large)
                Text("Hide Dock").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)
            
            // replace /System/Library/Lockdown/iPhoneDebug.pem
            Toggle(isOn: $enableReplacecert) {
                HStack(spacing: 20) {
                    Image(systemName: enableReplacecert ? "square.circle.fill" : "square.circle")
                        .foregroundColor(.green)
                        .imageScale(.large)
                Text("Replace iPhoneDebug.pem").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)
            
            // Enable Custom System Colors
            Toggle(isOn: $enableCustomSysColors) {
                HStack(spacing: 20) {
                    Image(systemName: enableCustomSysColors ? "drop.circle.fill" : "drop.circle")
                        .foregroundColor(.green)
                        .imageScale(.large)
                Text("Green System & Font Color").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)
            
            // Region Changer
            Toggle(isOn: $changeRegion) {
                HStack(spacing: 20) {
                    Image(systemName: changeRegion ? "globe.americas.fill" : "globe.americas")
                        .foregroundColor(.green)
                        .imageScale(.large)
                Text("Change Region").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)
            
            // Whitelist
            Toggle(isOn: $whitelist) {
                HStack(spacing: 20) {
                    Image(systemName: whitelist ? "slash.circle.fill" : "slash.circle")
                        .foregroundColor(.green)
                        .imageScale(.large)
                Text("Whitelist (Test)").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)
            
            // Supervise
            Toggle(isOn: $supervise) {
                HStack(spacing: 20) {
                    Image(systemName: supervise ? "eye.slash.circle.fill" : "eye.circle")
                        .foregroundColor(.green)
                        .imageScale(.large)
                Text("Supervise device").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)
            
            // Custom Font
            Toggle(isOn: $enableCustomFont) {
                HStack(spacing: 20) {
                    Image(systemName: enableCustomFont ? "a.circle.fill" : "a.circle")
                        .foregroundColor(.green)
                        .imageScale(.large)
                Text("Change Font (Hardcoded)").font(.headline)
                }
            }.frame(minWidth: 0, maxWidth: .infinity)
            .foregroundColor(.green)
            .tint(.green)
            Button("Apply Settings") {
                isTweaksPopoverPresented = false
            }
        }
        .padding()
    }
    
    private func enabledTweaks() -> [String] {
            var enabledTweaks: [String] = []
        if enableHideHomebar {
            enabledTweaks.append("enableHideHomebar")
        }
        if enableHideDock {
            enabledTweaks.append("HideDock")
        }
        if enableCustomFont {
            enabledTweaks.append("enableCustomFont")
        }
        if enableReplacecert {
            enabledTweaks.append("enableReplacecert")
        }
        if changeRegion {
            enabledTweaks.append("changeRegion")
        }
        if whitelist {
            enabledTweaks.append("whitelist")
        }
        if supervise {
            enabledTweaks.append("supervise")
        }

        return enabledTweaks
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

struct FileManagerUIKitViewControllerWrapper: UIViewControllerRepresentable {
    typealias UIViewControllerType = ViewController

    func makeUIViewController(context: Context) -> ViewController {
        return ViewController()
    }

    func updateUIViewController(_ uiViewController: ViewController, context: Context) {
    }
}

struct MaterialView: UIViewRepresentable {
    let material: UIBlurEffect.Style

    init(_ material: UIBlurEffect.Style) {
        self.material = material
    }

    func makeUIView(context: Context) -> UIVisualEffectView {
        UIVisualEffectView(effect: UIBlurEffect(style: material))
    }

    func updateUIView(_ uiView: UIVisualEffectView, context: Context) {
        uiView.effect = UIBlurEffect(style: material)
    }
}


/*
struct AXFileViewControllerUIKitViewControllerWrapper: UIViewControllerRepresentable {
    typealias UIViewControllerType = UITableViewController

    func makeUIViewController(context: Context) -> UITableViewController {
        return AXFileViewController()
    }

    func updateUIViewController(_ uiViewController: UITableViewController, context: Context) {
    }
}

struct withbarview: View {
    @State private var selectedview: String = "kfd"
    
    var targetview: some View {
        ZStack{
            switch selectedview {
            case "kfd":
                ContentView()
            case "jit":
                DirtyJITView()
            case "file":
                FileManagerUIKitViewControllerWrapper()
            default:
                ContentView()
            }
        }
    }
    
    var body: some View {
        ZStack{
            targetview
        }.toolbar {
            ToolbarItem(placement: .bottomBar) {
                Spacer()
            }
            ToolbarItem(placement: .bottomBar) {
                Image(systemName: "snowflake")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 32, height: 32)
                    .onTapGesture{
                        selectedview = "kfd"
                        print(selectedview)
                    }
            }
            ToolbarItem(placement: .bottomBar) {
                Spacer()
            }
            ToolbarItem(placement: .bottomBar) {
                Image(systemName: "app.connected.to.app.below.fill")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 32, height: 32)
                    .onTapGesture{
                        selectedview = "jit"
                        print(selectedview)
                    }
            }
            ToolbarItem(placement: .bottomBar) {
                Spacer()
            }
            ToolbarItem(placement: .bottomBar) {
                Image(systemName: "pc")
                    .resizable()
                    .scaledToFit()
                    .frame(width: 32, height: 32)
                    .onTapGesture{
                        selectedview = "file"
                        print(selectedview)
                    }
            }
            ToolbarItem(placement: .bottomBar) {
                Spacer()
            }
        }
    }
}
*/
