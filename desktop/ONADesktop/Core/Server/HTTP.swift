import Foundation

/// A minimal HTTP/1.x request reader for the phone protocol: one request per connection, small JSON bodies.
public struct HTTPRequest: Equatable, Sendable {
    public let method: String
    public let path: String
    /// Header names in lower case, values trimmed, in arrival order.
    public let headers: [Header]
    public let body: Data

    public struct Header: Equatable, Sendable {
        public let name: String
        public let value: String
        public init(_ name: String, _ value: String) { self.name = name; self.value = value }
    }

    public static let maxHeader = 16 * 1024
    public static let maxBody = 16 * 1024

    public init(method: String, path: String, headers: [Header] = [], body: Data) {
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body
    }

    public enum HeaderValue: Equatable, Sendable {
        case absent
        case one(String)
        case repeated
    }

    public func header(_ name: String) -> HeaderValue {
        let values = headers.filter { $0.name == name }.map(\.value)
        switch values.count {
        case 0: return .absent
        case 1: return .one(values[0])
        default: return .repeated
        }
    }

    public enum ParseResult: Equatable, Sendable {
        /// More bytes are needed.
        case incomplete
        case request(HTTPRequest)
        /// HTTP status to answer with before closing.
        case invalid(Int)
    }

    /// Parses `buffer` (everything received so far on the connection).
    public static func parse(_ buffer: Data) -> ParseResult {
        guard let end = buffer.range(of: Data("\r\n\r\n".utf8)) else {
            return buffer.count > maxHeader ? .invalid(431) : .incomplete
        }
        guard end.lowerBound - buffer.startIndex <= maxHeader,
              let head = String(data: buffer[..<end.lowerBound], encoding: .utf8) else {
            return .invalid(431)
        }
        let lines = head.components(separatedBy: "\r\n")
        let requestLine = lines[0].split(separator: " ", omittingEmptySubsequences: false)
        guard requestLine.count == 3, requestLine[2].hasPrefix("HTTP/1."), requestLine[1].hasPrefix("/") else {
            return .invalid(400)
        }
        var length: Int?
        var headers: [Header] = []
        for line in lines.dropFirst() {
            // An empty value ("Origin:") is a header with an empty value, as on the Rust side.
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { return .invalid(400) }
            let name = parts[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = parts[1].trimmingCharacters(in: .whitespaces)
            if name == "content-length" {
                guard let number = Int(value), number >= 0, length == nil || length == number else {
                    return .invalid(400)
                }
                length = number
            }
            if name == "transfer-encoding" { return .invalid(400) }
            headers.append(Header(name, value))
        }
        let bodyLength = length ?? 0
        guard bodyLength <= maxBody else { return .invalid(413) }
        let bodyStart = end.upperBound
        guard buffer.count - (bodyStart - buffer.startIndex) >= bodyLength else { return .incomplete }
        let body = buffer[bodyStart..<(bodyStart + bodyLength)]
        return .request(HTTPRequest(method: String(requestLine[0]), path: String(requestLine[1]), headers: headers,
                                    body: Data(body)))
    }
}

public struct HTTPResponse: Sendable {
    public let status: Int
    /// The reply as JSON text. When `signature` is set it travels inside `{"reply": "<text>", "signature": "…"}`.
    public let reply: Data
    public var signature: String?
    /// `application/json` for replies; a file's own type for the wallet page.
    public let contentType: String

    public init(status: Int, json: [String: Any]) {
        self.status = status
        reply = (try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])) ?? Data("{}".utf8)
        contentType = "application/json; charset=utf-8"
    }

    /// A file sent as it is (the wallet page).
    public init(asset: Data, contentType: String) {
        status = 200
        reply = asset
        self.contentType = contentType
    }

    /// What is sent: the signed envelope, or the reply itself when unsigned.
    public var body: Data {
        guard let signature else { return reply }
        let envelope: [String: Any] = ["reply": String(decoding: reply, as: UTF8.self), "signature": signature]
        return (try? JSONSerialization.data(withJSONObject: envelope, options: [.sortedKeys])) ?? Data("{}".utf8)
    }

    public var bytes: Data {
        let reason = switch status {
        case 200: "OK"
        case 400: "Bad Request"
        case 403: "Forbidden"
        case 404: "Not Found"
        case 409: "Conflict"
        case 413: "Payload Too Large"
        case 431: "Request Header Fields Too Large"
        case 503: "Service Unavailable"
        default: "Error"
        }
        let body = self.body
        var out = Data("HTTP/1.0 \(status) \(reason)\r\n".utf8)
        out.append(Data("Content-Type: \(contentType)\r\nContent-Length: \(body.count)\r\n".utf8))
        out.append(Data("Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\n".utf8))
        out.append(Data("Connection: close\r\n\r\n".utf8))
        out.append(body)
        return out
    }
}
