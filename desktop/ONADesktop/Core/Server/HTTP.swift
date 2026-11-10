import Foundation

/// A minimal HTTP/1.x request reader for the phone protocol: one request per connection, small JSON bodies.
public struct HTTPRequest: Equatable, Sendable {
    public let method: String
    public let path: String
    public let body: Data

    public static let maxHeader = 16 * 1024
    public static let maxBody = 16 * 1024

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
        guard end.lowerBound <= maxHeader, let head = String(data: buffer[..<end.lowerBound], encoding: .utf8) else {
            return .invalid(431)
        }
        let lines = head.components(separatedBy: "\r\n")
        let requestLine = lines[0].split(separator: " ", omittingEmptySubsequences: false)
        guard requestLine.count == 3, requestLine[2].hasPrefix("HTTP/1."), requestLine[1].hasPrefix("/") else {
            return .invalid(400)
        }
        var length = 0
        for line in lines.dropFirst() {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            if parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "content-length" {
                guard let value = Int(parts[1].trimmingCharacters(in: .whitespaces)), value >= 0 else {
                    return .invalid(400)
                }
                length = value
            }
        }
        guard length <= maxBody else { return .invalid(413) }
        let bodyStart = end.upperBound
        guard buffer.count - (bodyStart - buffer.startIndex) >= length else { return .incomplete }
        let body = buffer[bodyStart..<(bodyStart + length)]
        return .request(HTTPRequest(method: String(requestLine[0]), path: String(requestLine[1]), body: Data(body)))
    }
}

public struct HTTPResponse: Sendable {
    public let status: Int
    public let body: Data

    public init(status: Int, json: [String: Any]) {
        self.status = status
        body = (try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])) ?? Data("{}".utf8)
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
        default: "Error"
        }
        var out = Data("HTTP/1.0 \(status) \(reason)\r\n".utf8)
        out.append(Data("Content-Type: application/json; charset=utf-8\r\nContent-Length: \(body.count)\r\n".utf8))
        out.append(Data("Cache-Control: no-store\r\nConnection: close\r\n\r\n".utf8))
        out.append(body)
        return out
    }
}
