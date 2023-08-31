/*
 * Copyright (c) 2023 hrtowii. All rights reserved.
 */

import SwiftUI
import MacDirtyCow
import KernelPatchfinder

enum JAILBREAK_RETURN_STATUS {
    case ERR_JAILBREAK
}

struct ContentView: View {
    @State private var kfd: UInt64 = 0
    
    @State private var puafPages = 2048
    @State private var puafMethod = 1
    @State private var kreadMethod = 2
    @State private var kwriteMethod = 2
    //tweak vars
    @State private var use_do_fun = false
    @State private var use_stage2 = false
    @State private var use_stage2_mdc = false
    @State private var use_mdc = false
    
    var puafPagesOptions = [16, 32, 64, 128, 256, 512, 1024, 2048]
    var puafMethodOptions = ["physpuppet", "smith"]
    var kreadMethodOptions = ["kqueue_workloop_ctl", "sem_open", "IOSurface"]
    var kwriteMethodOptions = ["dup", "sem_open", "IOSurface"]
    
    @State private var message = ""
    
    @State private var isSettingsPopoverPresented = false // Track the visibility of the settings popup
    
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
                
                
                Section(header: Text("bad things")) {
                    VStack(alignment: .leading, spacing: 20) {
                        Text("15.2< setuid(0)")
                            .onTapGesture{
                                stage2()
                                DispatchQueue.main.async {
                                    message = "got gid=0, uid=0!"
                                }
                            }.frame(minWidth: 0, maxWidth: .infinity)
                        Text("15.2< all")
                            .onTapGesture{
                                mineekpf(kfd)
                                stage2_all()
                                DispatchQueue.main.async {
                                    message = "jailbreaked!"
                                }
                            }.frame(minWidth: 0, maxWidth: .infinity)
                        Text("<15.3")
                            .onTapGesture{
                                do_fun()
                                DispatchQueue.main.async {
                                    message = "sucecss!"
                                }
                            }.frame(minWidth: 0, maxWidth: .infinity)
                        Text("mdc")
                            .onTapGesture{
                                func unsandboxing()  {
                                    do {
                                        try MacDirtyCow.unsandbox()
                                        DispatchQueue.main.async {
                                            message = "unsandboxed!"
                                        }
                                    } catch {
                                        print(error)
                                    }
                                }
                                unsandboxing()
                            }.frame(minWidth: 0, maxWidth: .infinity)
                        Text("kpf")
                            .onTapGesture{
                                func do_kpf() {
                                    KernelPatchfinder.running
                                }
                                do_kpf()
                            }.frame(minWidth: 0, maxWidth: .infinity)
                    }.foregroundColor(.green)
                    .padding(.vertical, 8)
                }
                
                Section(header: Text("open/close")) {
                    Button("kopen") {
                        kfd = do_kopen(UInt64(puafPages), UInt64(puafMethod), UInt64(kreadMethod), UInt64(kwriteMethod))
                    }.buttonStyle(BorderlessButtonStyle()).disabled(kfd != 0)
                    Button("kclose") {
                        do_kclose()
                        puafPages = 0
                        kfd = 0
                    }.buttonStyle(BorderlessButtonStyle()).disabled(kfd == 0)
                }
                Section(header: Text("Settings")) {
                    Button(action: {
                        isSettingsPopoverPresented.toggle()
                    }, label: {Text("Setting")})
                }.buttonStyle(BorderlessButtonStyle())
            }
            .accentColor(.green)
            .popover(isPresented: $isSettingsPopoverPresented, arrowEdge: .bottom) {
                settingsPopover
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
}
struct ContentView_Previews: PreviewProvider {
  static var previews: some View {
    ContentView()
  }
}
