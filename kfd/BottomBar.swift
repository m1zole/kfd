import SwiftUI
import BottomBar_SwiftUI

let items: [BottomBarItem] = [
    BottomBarItem(icon: "house.fill", title: "Home", color: .purple),
    BottomBarItem(icon: "heart", title: "Likes", color: .pink),
    BottomBarItem(icon: "person.fill", title: "Profile", color: .blue)
]

struct BasicView: View {
    let item: BottomBarItem

    var detailText: String {
    "\(item.title) Detail"
}

var followButton: some View {
    Button(action: openTwitter) {
        VStack {
            Text("Developed by Bezhan Odinaev")
                .font(.headline)
                .foregroundColor(item.color)

            Text("@smartvipere75")
                .font(.subheadline)
                .foregroundColor(.gray)
        }
    }
}

var destination: some View {
    Text(detailText)
        .navigationBarTitle(Text(detailText))
}

var navigateButton: some View {
    NavigationLink(destination: destination) {
        if(item.color == .blue){
            ContentView()
        } else if(item.color == .pink){
            DirtyJITView()
        } else {
            FileManagerUIKitViewControllerWrapper()
        }
    }
}

func openTwitter() {
    guard let url = URL(string: "https://twitter.com/smartvipere75") else {
        return
    }
    UIApplication.shared.open(url, options: [:], completionHandler: nil)
}

var body: some View {
    VStack {
        navigateButton
        }
    }
}

struct BarContentView : View {
    @State private var selectedIndex: Int = 0

    var selectedItem: BottomBarItem {
        items[selectedIndex]
    }

var body: some View {
        NavigationView {
            VStack {
                BasicView(item: selectedItem)
                    .navigationBarTitle(Text(selectedItem.title))
                    .toolbar {
                        ToolbarItem(placement: .bottomBar) {
                            BottomBar(selectedIndex: $selectedIndex, items: items)
                        }
                    }
                //BottomBar(selectedIndex: $selectedIndex, items: items)
            }
        }
    }
}
