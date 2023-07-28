import SwiftUI

struct ContentView: View {
    @State private var kfd: UInt64 = 0

    private let puafPagesOptions = [16, 32, 64, 128, 256, 512, 1024, 2048]
    @State private var puafPagesIndex = 7
    @State private var puafPages = 0

    private let puafMethodOptions = ["physpuppet", "smith"]
    @State private var puafMethod = 1

    private let kreadMethodOptions = ["kqueue_workloop_ctl", "sem_open"]
    @State private var kreadMethod = 1

    private let kwriteMethodOptions = ["dup", "sem_open"]
    @State private var kwriteMethod = 1

    var body: some View {
        NavigationView {
            VStack {
                Form {
                    Section() {
                        NavigationLink(destination: SettingsView(puafPagesIndex: $puafPagesIndex, puafMethod: $puafMethod, kreadMethod: $kreadMethod, kwriteMethod: $kwriteMethod)) {
                            HStack {
                                Text("Settings")
                                    .frame(minWidth: 0, maxWidth: .infinity, alignment: .center)
                                    .foregroundColor(.purple)
                            }
                            .contentShape(Rectangle())
                        }
                        Button("Open Kernel") {
                                puafPages = puafPagesOptions[puafPagesIndex]
                                kfd = kopen(UInt64(puafPages), UInt64(puafMethod), UInt64(kreadMethod), UInt64(kwriteMethod))
                            }.disabled(kfd != 0)
                            .frame(minWidth: 0, maxWidth: .infinity)
                            .foregroundColor(kfd == 0 ? .purple : .purple.opacity(0.5))
                        Button("Close Kernel") {
                                kclose(kfd)
                                puafPages = 0
                                kfd = 0
                            }.disabled(kfd == 0)
                            .frame(minWidth: 0, maxWidth: .infinity)
                            .foregroundColor(kfd != 0 ? .purple : .purple.opacity(0.5))

                        if kfd != 0 {
                            VStack(alignment: .leading) {
                                Text("Success!").foregroundColor(.green)
                                Text("Look at output in Xcode")
                            }
                            .frame(minWidth: 0, maxWidth: .infinity)
                        }
                    }
                    .listRowBackground(Color.clear)
                }
                .navigationBarTitle("KFD", displayMode: .inline)
            }
        }
    }
}

struct SettingsView: View {
    @Binding var puafPagesIndex: Int
    @Binding var puafMethod: Int
    @Binding var kreadMethod: Int
    @Binding var kwriteMethod: Int

    private let puafPagesOptions = [16, 32, 64, 128, 256, 512, 1024, 2048]
    private let puafMethodOptions = ["physpuppet", "smith"]
    private let kreadMethodOptions = ["kqueue_workloop_ctl", "sem_open"]
    private let kwriteMethodOptions = ["dup", "sem_open"]

    var body: some View {
        Form {
            Section(header: Text("Settings")) {
                Picker("puaf pages:", selection: $puafPagesIndex) {
                    ForEach(0 ..< puafPagesOptions.count, id: \.self) {
                        Text(String(self.puafPagesOptions[$0]))
                    }
                }

                Picker("puaf method:", selection: $puafMethod) {
                    ForEach(0 ..< puafMethodOptions.count, id: \.self) {
                        Text(self.puafMethodOptions[$0])
                    }
                }

                Picker("kread method:", selection: $kreadMethod) {
                    ForEach(0 ..< kreadMethodOptions.count, id: \.self) {
                        Text(self.kreadMethodOptions[$0])
                    }
                }

                Picker("kwrite method:", selection: $kwriteMethod) {
                    ForEach(0 ..< kwriteMethodOptions.count, id: \.self) {
                        Text(self.kwriteMethodOptions[$0])
                    }
                }
            }
        }
        .navigationBarTitle("Settings", displayMode: .inline)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
