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
        .onAppear {
            ipPrefix = getLocalIPPrefix()
            triggerLocalNetworkPrivacyAlert()
        }
    }

    func getLocalIPPrefix() -> String {
        var prefix = "192.168.1"
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0 else { return prefix }
        guard let firstAddr = ifaddr else { return prefix }
        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let addr = ptr.pointee.ifa_addr.pointee
            if addr.sa_family == UInt8(AF_INET) {
                let name = String(cString: ptr.pointee.ifa_name)
                if name == "en0" {
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(ptr.pointee.ifa_addr, socklen_t(addr.sa_len), &hostname, socklen_t(hostname.count), nil, socklen_t(0), NI_NUMERICHOST) == 0 {
                        let ipString = String(cString: hostname)
                        let components = ipString.split(separator: ".")
                        if components.count == 4 {
                            prefix = "\(components[0]).\(components[1]).\(components[2])"
                        }
                    }
                }
            }
        }
        freeifaddrs(ifaddr)
        return prefix
    }

    func triggerLocalNetworkPrivacyAlert() {
        let host = NWEndpoint.Host("\(ipPrefix).1")
        let port = NWEndpoint.Port(rawValue: 80)!
        let connection = NWConnection(host: host, port: port, using: .tcp)
        connection.start(queue: .global())
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) { connection.cancel() }
    }

    func startScan() {
        isScanning = true
        scannedCount = 0
        for i in 1...255 { results[i] = nil }
        
        DispatchQueue.global(qos: .userInitiated).async {
            // 维持安全并发量，防止 iOS 强制掐断网络
            let semaphore = DispatchSemaphore(value: 12) 
            
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
    
    func checkIPHybrid(ip: String, completion: @escaping (Bool) -> Void) {
        DispatchQueue.global().async {
            var pingSuccess = false
            
            // 🚀 核心战术调整：4 次深度尝试 + 0.3秒缓慢退避
            // 这给了路由器完整的 ARP 广播时间，休眠设备也绝对有时间被唤醒
            for attempt in 1...4 { 
                if self.nativeICMPPing(ip: ip, sequence: UInt16(attempt)) {
                    pingSuccess = true
                    break
                }
                if attempt < 4 {
                    Thread.sleep(forTimeInterval: 0.3) 
                }
            }
            
            if pingSuccess {
                completion(true)
                return
            }
            
            // Ping 彻底失败的保底 TCP 探测
            let portsToTest: [UInt16] = [80, 443, 22, 135, 445, 554, 5000, 5353, 8080]
            var hasCompleted = false
            let lock = NSLock()
            var connections: [NWConnection] = []
            
            func markOnline() {
                lock.lock()
                defer { lock.unlock() }
                if !hasCompleted {
                    hasCompleted = true
                    completion(true)
                    connections.forEach { $0.cancel() }
                }
            }

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
                    case .ready: markOnline()
                    case .failed(let error):
                        if error.debugDescription.contains("refused") || error.debugDescription.contains("61") {
                            markOnline()
                        }
                    default: break
                    }
                }
                connection.start(queue: queue)
            }
            
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
    }

    // 🚀 彻底重写的内核级 Ping 
    func nativeICMPPing(ip: String, sequence: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        if fd < 0 {
            Thread.sleep(forTimeInterval: 0.1)
            return false
        }
        defer { close(fd) }

        var tv = timeval(tv_sec: 1, tv_usec: 0) // 1 秒超时
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        if inet_pton(AF_INET, ip, &addr.sin_addr) <= 0 { return false }

        // 构造满血版的 64 字节苹果标准 Ping 包
        var packet = [UInt8](repeating: 0, count: 64) 
        packet[0] = 8 // Type: Echo Request
        packet[1] = 0 // Code
        packet[2] = 0 // Checksum
        packet[3] = 0
        packet[4] = 0 // ID
        packet[5] = 0 
        packet[6] = UInt8(sequence >> 8)
        packet[7] = UInt8(sequence & 0x00FF)
        
        // 填充标准的数据载荷，避免某些严苛的防火墙拦截空包
        for i in 8..<64 {
            packet[i] = UInt8(i % 256)
        }

        // 🚀 核心修复：废弃 connect，使用 sendto 彻底激活内核的 ARP 寻址机制
        var sent: Int = 0
        withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                sent = sendto(fd, packet, packet.count, 0, ptr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        
        if sent <= 0 { return false }

        var buffer = [UInt8](repeating: 0, count: 128)
        var fromAddr = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
        
        let startTime = Date()
        
        while Date().timeIntervalSince(startTime) < 1.0 {
            // 🚀 核心修复：使用 recvfrom 接收并校验来源 IP
            let received = withUnsafeMutablePointer(to: &fromAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                    recvfrom(fd, &buffer, buffer.count, 0, ptr, &fromLen)
                }
            }
            
            if received >= 8 {
                // 1. 判断是否是 Echo Reply 回应包 (Type = 0)
                if buffer[0] == 0 {
                    // 2. 物理级防串线：严格对比回包的 IP 和我们请求的目标 IP 是否一致！
                    if fromAddr.sin_addr.s_addr == addr.sin_addr.s_addr {
                        return true
                    }
                }
            }
        }
        return false
    }
}