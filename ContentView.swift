import SwiftUI
import Network
import Darwin

struct ContentView: View {
    @State private var ipPrefix: String = "192.168.1"
    @State private var results: [Int: Bool?] = [:] 
    @State private var isScanning = false
    @State private var scannedCount = 0

    let columns = Array(repeating: GridItem(.flexible(), spacing: 5), count: 10)

    var body: some View {
        VStack {
            Text("局域网 IP 扫描器 (究极混合版)").font(.headline).padding()
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
        .onAppear {
            // 核心修复 1：APP打开时，强制触发 iOS 局域网权限弹窗
            triggerLocalNetworkPrivacyAlert()
        }
    }

    // 发送一个隐形的 TCP 请求，逼迫系统索要局域网权限
    func triggerLocalNetworkPrivacyAlert() {
        let host = NWEndpoint.Host("\(ipPrefix).1")
        let port = NWEndpoint.Port(rawValue: 80)!
        let connection = NWConnection(host: host, port: port, using: .tcp)
        connection.start(queue: .global())
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            connection.cancel()
        }
    }

    func startScan() {
        isScanning = true
        scannedCount = 0
        for i in 1...255 { results[i] = nil }
        
        DispatchQueue.global(qos: .userInitiated).async {
            // 控制混合扫描的并发量，防止挤爆系统连接池
            let semaphore = DispatchSemaphore(value: 30) 
            
            for i in 1...255 {
                semaphore.wait()
                let ip = "\(self.ipPrefix).\(i)"
                
                self.checkIPHybrid(ip: ip) { isOnline in
                    DispatchQueue.main.async {
                        self.results[i] = isOnline
                        self.scannedCount += 1
                        if self.scannedCount == 255 {
                            self.isScanning = false
                        }
                    }
                    semaphore.signal()
                }
            }
        }
    }
    
    // 🚀 核心修复 2：究极融合检测（ICMP Ping + TCP 端口双管齐下）
    func checkIPHybrid(ip: String, completion: @escaping (Bool) -> Void) {
        var hasCompleted = false
        let lock = NSLock()
        var connections: [NWConnection] = []
        
        // 标记设备在线，并立刻取消所有其他无用的探测，节约性能
        func markOnline() {
            lock.lock()
            defer { lock.unlock() }
            if !hasCompleted {
                hasCompleted = true
                completion(true)
                connections.forEach { $0.cancel() }
            }
        }

        // 策略 A：启动底层 ICMP Ping (专治不开放端口的 IoT 设备和苹果设备)
        DispatchQueue.global().async {
            for attempt in 1...2 {
                if self.nativeICMPPing(ip: ip) {
                    markOnline()
                    return
                }
                if attempt < 2 { Thread.sleep(forTimeInterval: 0.1) }
            }
        }

        // 策略 B：同时启动 TCP 关键端口探测 (专治开启防火墙禁 Ping 的 Windows 电脑)
        let portsToTest: [UInt16] = [80, 443, 135, 445, 5353]
        let queue = DispatchQueue(label: "com.scanner.tcp.\(ip)", attributes: .concurrent)
        
        for portNum in portsToTest {
            let host = NWEndpoint.Host(ip)
            let port = NWEndpoint.Port(rawValue: portNum)!
            let connection = NWConnection(host: host, port: port, using: .tcp)
            
            lock.lock()
            connections.append(connection)
            lock.unlock()
            
            connection.stateUpdateHandler = { state in
                if hasCompleted { return }
                switch state {
                case .ready:
                    markOnline()
                case .failed(let error):
                    let errString = error.debugDescription
                    if errString.contains("refused") || errString.contains("61") || errString.contains("ECONNREFUSED") {
                        markOnline()
                    }
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
        
        // 全局超时：如果 1.5 秒内 Ping 和 TCP 全都石沉大海，才彻底判定离线
        DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
            lock.lock()
            defer { lock.unlock() }
            if !hasCompleted {
                hasCompleted = true
                completion(false)
                connections.forEach { $0.cancel() }
            }
        }
    }

    // 底层 C 语言 ICMP Ping 实现
    func nativeICMPPing(ip: String) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var tv = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        if inet_pton(AF_INET, ip, &addr.sin_addr) <= 0 { return false }

        let packet: [UInt8] = [8, 0, 0, 0, 0, 0, 0, 0]

        let sent = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                sendto(fd, packet, packet.count, 0, ptr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if sent <= 0 { return false }

        var buffer = [UInt8](repeating: 0, count: 64)
        var fromAddr = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)

        let received = withUnsafeMutablePointer(to: &fromAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                recvfrom(fd, &buffer, buffer.count, 0, ptr, &fromLen)
            }
        }

        if received >= 8 && buffer[0] == 0 {
            return true
        }
        return false
    }
}
