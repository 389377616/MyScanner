import SwiftUI
import Network

struct ContentView: View {
    @State private var ipPrefix: String = "192.168.1"
    @State private var results: [Int: Bool?] = [:] // nil: 未扫描/离线, true: 在线
    @State private var isScanning = false
    @State private var scannedCount = 0

    let columns = Array(repeating: GridItem(.flexible(), spacing: 5), count: 10)

    var body: some View {
        VStack {
            Text("局域网 IP 扫描器").font(.headline).padding()
            HStack {
                TextField("IP 段 (如 192.168.1)", text: $ipPrefix)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .keyboardType(.numbersAndPunctuation)
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
        // 确保 UI 延伸到安全区，利用全部屏幕空间
        .edgesIgnoringSafeArea(.bottom) 
    }

    func startScan() {
        isScanning = true
        scannedCount = 0
        for i in 1...255 { results[i] = nil }
        
        for i in 1...255 {
            let ip = "\(ipPrefix).\(i)"
            checkIP(ip: ip) { isOnline in
                DispatchQueue.main.async {
                    self.results[i] = isOnline
                    self.scannedCount += 1
                    // 255个IP全测完后恢复按钮状态
                    if self.scannedCount == 255 {
                        self.isScanning = false
                    }
                }
            }
        }
    }
    
    // 使用 Network 框架进行并发 TCP 探测，真实检测设备存活
    func checkIP(ip: String, completion: @escaping (Bool) -> Void) {
        let host = NWEndpoint.Host(ip)
        // 使用 80 端口作为敲门砖
        let port = NWEndpoint.Port(rawValue: 80)!
        
        let connection = NWConnection(host: host, port: port, using: .tcp)
        var hasCompleted = false
        
        connection.stateUpdateHandler = { state in
            if hasCompleted { return }
            
            switch state {
            case .ready:
                // 端口开放，设备绝对在线
                hasCompleted = true
                connection.cancel()
                completion(true)
                
            case .failed(let error):
                hasCompleted = true
                let errString = error.debugDescription
                // 核心逻辑：如果收到“拒绝连接(ECONNREFUSED/61)”，说明设备虽然没开网页服务，但网络层成功拦截并拒绝了我们，证明设备在线！
                if errString.contains("refused") || errString.contains("61") || errString.contains("ECONNREFUSED") {
                    completion(true)
                } else {
                    completion(false)
                }
                connection.cancel()
                
            default:
                break
            }
        }
        
        connection.start(queue: .global())
        
        // 局域网响应极快，设定 0.5 秒超时即可（超时说明 IP 空置）
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) {
            if !hasCompleted {
                hasCompleted = true
                connection.cancel()
                completion(false)
            }
        }
    }
}
