import SwiftUI
import Darwin // 引入底层 C 语言套接字库

struct ContentView: View {
    @State private var ipPrefix: String = "192.168.1"
    @State private var results: [Int: Bool?] = [:] // nil: 未扫描/离线, true: 在线
    @State private var isScanning = false
    @State private var scannedCount = 0

    let columns = Array(repeating: GridItem(.flexible(), spacing: 5), count: 10)

    var body: some View {
        VStack {
            Text("局域网 IP 扫描器 (专业高精度版)").font(.headline).padding()
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
        // 解除底部全面屏安全区限制
        .edgesIgnoringSafeArea(.bottom)
    }

    func startScan() {
        isScanning = true
        scannedCount = 0
        for i in 1...255 { results[i] = nil }
        
        DispatchQueue.global(qos: .userInitiated).async {
            // 控制并发量，防止过大的并发导致系统套接字被挤爆或路由器拥堵
            let semaphore = DispatchSemaphore(value: 64)
            
            for i in 1...255 {
                semaphore.wait()
                let ip = "\(self.ipPrefix).\(i)"
                
                DispatchQueue.global().async {
                    var isOnline = false
                    
                    // 🚀 黄金策略：最多重试 3 次，对抗局域网 ARP 丢包和休眠设备
                    for attempt in 1...3 {
                        if self.nativeICMPPing(ip: ip) {
                            isOnline = true
                            break // 只要通了一次，立刻判定在线并退出重试，极大加快扫描速度
                        } else {
                            // 如果没通，动态退避：第一次等 0.1秒，第二次等 0.2秒
                            // 给休眠设备唤醒芯片和路由器寻址的时间
                            if attempt < 3 {
                                Thread.sleep(forTimeInterval: Double(attempt) * 0.1)
                            }
                        }
                    }
                    
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
    
    // 🚀 调用 Darwin 底层 API 手捏真正的 ICMP 数据包
    func nativeICMPPing(ip: String) -> Bool {
        // 创建 Datagram 类型的 ICMP 套接字 (Apple 专门放开的无特权 Ping 接口)
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        // 设置接收超时时间为 1 秒
        var tv = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // 构造目标地址
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        // 将字符串 IP 转换为网络字节序，如果 IP 不合法直接返回
        if inet_pton(AF_INET, ip, &addr.sin_addr) <= 0 { return false }

        // 构造最精简的 ICMP Echo Request 包头 (只需 8 字节)
        // 结构: [类型:8, 代码:0, 校验和:0,0, 标识符:0,0, 序列号:0,0]
        // 极客魔法：使用 SOCK_DGRAM 发送时，Mac/iOS 内核会自动帮我们计算校验和并填充正确的标识符！
        let packet: [UInt8] = [8, 0, 0, 0, 0, 0, 0, 0]

        // 发送数据包
        let sent = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                sendto(fd, packet, packet.count, 0, ptr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if sent <= 0 { return false }

        // 准备接收回包
        var buffer = [UInt8](repeating: 0, count: 64)
        var fromAddr = sockaddr_in()
        var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)

        let received = withUnsafeMutablePointer(to: &fromAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                recvfrom(fd, &buffer, buffer.count, 0, ptr, &fromLen)
            }
        }

        // 如果收到的数据超过 8 字节，并且包头的 Type 字段为 0 (Echo Reply，即 Ping 回应包)
        if received >= 8 && buffer[0] == 0 {
            return true
        }
        
        return false
    }
}