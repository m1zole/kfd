//
//  ContentView.swift
//  DirtyJIT
//
//  Created by Анохин Юрий on 03.03.2023.
//

import SwiftUI
import MacDirtyCow

@available(iOS 15.0, *)
struct DirtyJITView: View {
    @AppStorage("firstTime") private var firstTime = true
    @State var apps2: [SBApp2] = []
    @State private var searchText = ""
    @State private var presentAlert = false
    
    var body: some View {
        VStack {
            AppsView(searchText: $searchText, apps2: apps2)
                .navigationBarTitle("DirtyJIT", displayMode: .inline)
                .toolbar {
                    Button {
                        presentAlert = true
                    } label: {
                        Image(systemName: "magnifyingglass")
                    }
                }
        }
//        .sheet(isPresented: $firstTime, content: SetupView.init)
        .onAppear {
            UIApplication.shared.alert(title: "Loading", body: "Please wait...", withButton: false)
            
            func unsandboxing()  {
                do {
                    try MacDirtyCow.unsandbox()
                } catch {
                    print(error)
                }
            }
            unsandboxing()
            DispatchQueue.main.asyncAfter(deadline: .now() + 3) {
                UIApplication.shared.dismissAlert(animated: false)
                
                do {
                    apps2 = try ApplicationManager2.getApps()
                } catch {
                    UIApplication.shared.alert(title: "Error", body: error.localizedDescription, withButton: true)
                }
            }
        }
        .textFieldAlert(isPresented: $presentAlert) { () -> TextFieldAlert in
            TextFieldAlert(title: "Enter app name", message: "Search for the app you want to find, make sure you spell it right!", text: Binding<String?>($searchText))
        }
    }
}
