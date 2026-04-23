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
        .edgesIgnoringSafeArea(.bottom)
    }

    func startScan() {
        isScanning = true
        scannedCount = 0
        for i in 1...255 { results[i] = nil }
        
        // 放到后台线程处理，避免阻塞 UI
        DispatchQueue.global(qos: .userInitiated).async {
            // 核心修复 1：设置信号量，全局最多允许 15 个并发连接，防止路由器丢包
            let semaphore = DispatchSemaphore(value: 15)
            
            for i in 1...255 {
                semaphore.wait() // 申请通行证，满15个就排队等待
                
                let ip = "\(self.ipPrefix).\(i)"
                self.checkIP(ip: ip) { isOnline in
                    DispatchQueue.main.async {
                        self.results[i] = isOnline
                        self.scannedCount += 1
                        if self.scannedCount == 255 {
                            self.isScanning = false
                        }
                    }
                    semaphore.signal() // 扫描完毕，释放一个名额给后面的 IP
                }
            }
        }
    }
    
    // 核心修复 2：多端口递归探测 + 延长超时
    func checkIP(ip: String, completion: @escaping (Bool) -> Void) {
        // 测试组合：网页端口(80/443), Windows必备端口(135), Linux/NAS常用端口(22)
        let portsToTest: [UInt16] = [80, 443, 135, 22]
        var currentPortIndex = 0
        
        func testNextPort() {
            if currentPortIndex >= portsToTest.count {
                completion(false) // 所有端口都没回应，判定为离线
                return
            }
            
            let portNum = portsToTest[currentPortIndex]
            let host = NWEndpoint.Host(ip)
            let port = NWEndpoint.Port(rawValue: portNum)!
            let connection = NWConnection(host: host, port: port, using: .tcp)
            var hasCompleted = false
            
            connection.stateUpdateHandler = { state in
                if hasCompleted { return }
                
                switch state {
                case .ready:
                    hasCompleted = true
                    connection.cancel()
                    completion(true) // 端口开放，设备在线
                    
                case .failed(let error):
                    hasCompleted = true
                    let errString = error.debugDescription
                    // 底层网络主动拒绝，说明设备肯定存在于内网
                    if errString.contains("refused") || errString.contains("61") || errString.contains("ECONNREFUSED") {
                        completion(true)
                    } else {
                        // 超时或其他错误，换下一个端口继续测
                        currentPortIndex += 1
                        testNextPort()
                    }
                    connection.cancel()
                    
                default:
                    break
                }
            }
            
            connection.start(queue: .global())
            
            // 核心修复 3：将超时时间放宽到 1.5 秒，照顾弱网和休眠设备
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                if !hasCompleted {
                    hasCompleted = true
                    connection.cancel()
                    currentPortIndex += 1
                    testNextPort() // 当前端口超时，直接测下一个
                }
            }
        }
        
        testNextPort()
    }
}
