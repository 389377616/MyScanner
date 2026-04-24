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
                    if getnameinfo(ptr.pointee.ifa_addr, socklen_t(addr.sa_len),
                                   &hostname, socklen_t(hostname.count),
                                   nil, socklen_t(0), NI_NUMERICHOST) == 0 {
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
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            connection.cancel()
        }
    }

    func startScan() {
        isScanning = true
        scannedCount = 0
        for i in 1...255 { results[i] = nil }
        
        DispatchQueue.global(qos: .userInitiated).async {
            let semaphore = DispatchSemaphore(value: 40) // 提升并发到 40
            
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

        // 策略 A：采用满血版的 ICMP Ping
        DispatchQueue.global().async {
            for attempt in 1...3 {
                if self.nativeICMPPing(ip: ip) {
                    markOnline()
                    return
                }
                if attempt < 3 { Thread.sleep(forTimeInterval: 0.1) } // 失败避退，防网络拥塞
            }
        }

        // 策略 B：TCP 端口探测作为保底补充
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

    // 🚀 核心重构：防串线、带载荷的标准 Ping
    func nativeICMPPing(ip: String) -> Bool {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        // 设置超时
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        if inet_pton(AF_INET, ip, &addr.sin_addr) <= 0 { return false }

        // 🟢 关键改进 1：强行绑定套接字和目标 IP！
        // 这样底层的 C 内核会帮我们过滤掉所有其他 IP 的回包，彻底解决高并发串线漏包问题
        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                connect(fd, ptr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { return false }

        // 🟢 关键改进 2：伪造标准的 64 字节数据包 (8字节报头 + 56字节载荷)
        // 避免防火墙拦截无特征的 8 字节空包
        var packet = [UInt8](repeating: 97, count: 64) // 填充字母 'a' 作为 Payload
        packet[0] = 8 // Type: Echo Request
        packet[1] = 0 // Code
        packet[2] = 0 // Checksum (内核代填)
        packet[3] = 0
        packet[4] = 0 // ID
        packet[5] = 0
        packet[6] = 0 // Sequence
        packet[7] = 1 

        // 绑定后可以直接用 send，无需 sendto
        let sent = send(fd, packet, packet.count, 0)
        if sent <= 0 { return false }

        var buffer = [UInt8](repeating: 0, count: 128)
        let startTime = Date()
        
        // 使用循环读取，只要在 1 秒内读到目标回包即判定在线
        while Date().timeIntervalSince(startTime) < 1.0 {
            let received = recv(fd, &buffer, buffer.count, 0)
            if received >= 8 {
                // 判断是否为 Echo Reply 回应包 (Type = 0)
                if buffer[0] == 0 {
                    return true
                }
            }
        }
        return false
    }
}