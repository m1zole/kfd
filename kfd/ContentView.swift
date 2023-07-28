/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

import SwiftUI

struct ContentView: View {
    @State private var kfd: UInt64 = 0

    private var puafPagesOptions = [16, 32, 64, 128, 256, 512, 1024, 2048]
    @State private var puafPagesIndex = 7
    @State private var puafPages = 0

    private var puafMethodOptions = ["physpuppet", "smith"]
    @State private var puafMethod = 1

    private var kreadMethodOptions = ["kqueue_workloop_ctl", "sem_open"]
    @State private var kreadMethod = 1

    private var kwriteMethodOptions = ["dup", "sem_open"]
    @State private var kwriteMethod = 1

    var body: some View {
        NavigationView {
            Form {
                Section {
                    Picker(selection: $puafPagesIndex, label: Text("puaf pages:")) {
                        ForEach(0 ..< puafPagesOptions.count, id: \.self) {
                            Text(String(self.puafPagesOptions[$0]))
                        }
                    }.disabled(kfd != 0)
                }

                Section {
                    Picker(selection: $puafMethod, label: Text("puaf method:")) {
                        ForEach(0 ..< puafMethodOptions.count, id: \.self) {
                            Text(self.puafMethodOptions[$0])
                        }
                    }.disabled(kfd != 0)
                }

                Section {
                    Picker(selection: $kreadMethod, label: Text("kread method:")) {
                        ForEach(0 ..< kreadMethodOptions.count, id: \.self) {
                            Text(self.kreadMethodOptions[$0])
                        }
                    }.disabled(kfd != 0)
                }

                Section {
                    Picker(selection: $kwriteMethod, label: Text("kwrite method:")) {
                        ForEach(0 ..< kwriteMethodOptions.count, id: \.self) {
                            Text(self.kwriteMethodOptions[$0])
                        }
                    }.disabled(kfd != 0)
                }

                Section {
                    HStack {
                        Button("Open Kernel") {
                            puafPages = puafPagesOptions[puafPagesIndex]
                            kfd = do_kopen(UInt64(puafPages), UInt64(puafMethod), UInt64(kreadMethod), UInt64(kwriteMethod))
                            do_fun(kfd)
//                            execCmd(args: [CommandLine.arguments[0], "whoami"])
                        }.disabled(kfd != 0)
                        .frame(minWidth: 0, maxWidth: .infinity)

                        Button("Close Kernel") {
                            do_kclose(kfd)
                            puafPages = 0
                            kfd = 0
                        }.disabled(kfd == 0)
                        .frame(minWidth: 0, maxWidth: .infinity)
                    }.buttonStyle(.bordered)
                }.listRowBackground(Color.clear)

                Button("Respring") {
                    puafPages = 0
                    kfd = 0
                    do_respring()
                }.frame(minWidth: 0, maxWidth: .infinity)

                Button("Backboard respring") {
                    puafPages = 0
                    kfd = 0
                    do_bbrespring()
                }.frame(minWidth: 0, maxWidth: .infinity)

                if kfd != 0 {
                    Section {
                        VStack {
                            Text("Success!").foregroundColor(.green)
                            Text("Look at output in Xcode")
                        }.frame(minWidth: 0, maxWidth: .infinity)
                    }.listRowBackground(Color.clear)
                }
            }.navigationBarTitle(Text("kfd"), displayMode: .inline)
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}
