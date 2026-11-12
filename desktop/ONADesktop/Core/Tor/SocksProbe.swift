import Darwin
import Foundation

/// Checks that an onion address answers, through tor's SOCKS port on 127.0.0.1 (RFC 1928, no authentication, name
/// resolved by tor). The `hostname` file of an onion service exists before the service is published, and stays from
/// one launch to the next: only a stream that Tor reports as connected shows that the phone can reach this Mac.
enum SocksProbe {
    enum Failure: Error, Equatable {
        case badHost
        case socket(String)
        case refused
        case reply(UInt8)
    }

    /// A port free on 127.0.0.1 right now, for tor's SOCKS port.
    static func freeLocalPort() -> UInt16? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var address = loopback(port: 0)
        guard withSockaddr(&address, { bind(fd, $0, $1) }) == 0 else { return nil }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &address, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }) == 0 else { return nil }
        return UInt16(bigEndian: address.sin_port)
    }

    /// Opens a stream to `host:port` through the SOCKS5 proxy on 127.0.0.1:`socksPort`, then closes it. Blocking:
    /// call off the main actor.
    static let missingClientAuth: UInt8 = 0xF4

    static func reach(socksPort: UInt16, host: String, port: UInt16 = 80, timeout: TimeInterval = 60) throws(Failure) {
        let name = Array(host.utf8)
        guard !name.isEmpty, name.count <= 255 else { throw .badHost }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw .socket("socket") }
        defer { close(fd) }
        var limit = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size))
        // A write after tor closed the connection must fail, not kill the app with SIGPIPE.
        var noSigpipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, socklen_t(MemoryLayout<Int32>.size))
        var address = loopback(port: socksPort)
        guard withSockaddr(&address, { connect(fd, $0, $1) }) == 0 else { throw .socket("connect") }
        try send(fd, [5, 1, 0])
        guard try receive(fd, 2) == [5, 0] else { throw .refused }
        try send(fd, [5, 1, 0, 3, UInt8(name.count)] + name + [UInt8(port >> 8), UInt8(port & 0xff)])
        let reply = try receive(fd, 4)
        guard reply[0] == 5 else { throw .refused }
        // 0xF4 (ExtendedErrors): "onion service missing client authorization". tor found the descriptor, restricted
        // to client keys this app does not hold: the service is published, and the phone's key opens it.
        guard reply[1] == 0 || reply[1] == missingClientAuth else { throw .reply(reply[1]) }
    }

    static func loopback(port: UInt16) -> sockaddr_in {
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        return address
    }

    static func withSockaddr(_ address: inout sockaddr_in, _ body: (UnsafePointer<sockaddr>, socklen_t) -> Int32)
        -> Int32 {
        withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
    }

    static func send(_ fd: Int32, _ bytes: [UInt8]) throws(Failure) {
        var sent = 0
        while sent < bytes.count {
            let n = bytes[sent...].withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
            guard n > 0 else { throw .socket("send") }
            sent += n
        }
    }

    static func receive(_ fd: Int32, _ count: Int) throws(Failure) -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = buffer[got...].withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
            guard n > 0 else { throw .socket("recv") }
            got += n
        }
        return buffer
    }
}
