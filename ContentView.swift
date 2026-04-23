import SwiftUI

struct ContentView: View {
    @State private var ipPrefix: String = "192.168.1"
    @State private var results: [Int: Bool?] = [:] // Int 是末位 IP, Bool? 是在线状态
    @State private var isScanning = false

    let columns = Array(repeating: GridItem(.flexible(), spacing: 5), count: 10)

    var body: some View {
        VStack {
            Text("局域网 IP 扫描器").font(.headline).padding()
            HStack {
                TextField("IP 段 (如 192.168.1)", text: $ipPrefix)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                Button(action: startScan) {
                    Text(isScanning ? "扫描中" : "开始").padding(10)
                        .background(isScanning ? Color.gray : Color.blue)
                        .foregroundColor(.white).cornerRadius(8)
                }.disabled(isScanning)
            }.padding()

            ScrollView {
                LazyVGrid(columns: columns, spacing: 5) {
                    ForEach(1...255, id: \.self) { i in
                        Rectangle()
                            .fill(results[i] == true ? Color.green : (results[i] == false ? Color.red : Color.gray.opacity(0.3)))
                            .frame(height: 30)
                            .overlay(Text("\(i)").font(.system(size: 8)).foregroundColor(.white))
                    }
                }.padding()
            }
        }
    }

    func startScan() {
        isScanning = true
        for i in 1...255 { results[i] = nil }
        
        for i in 1...255 {
            let ip = "\(ipPrefix).\(i)"
            // 这里为了演示界面效果使用模拟扫描，实际 Ping 需调用 ICMP
            DispatchQueue.global().asyncAfter(deadline: .now() + Double.random(in: 0.1...2.0)) {
                DispatchQueue.main.async {
                    results[i] = Bool.random()
                    if i == 255 { isScanning = false }
                }
            }
        }
    }
}
