import Foundation
import OnaCore

/// One ona-core instance (Rust, desktop/OnaCoreBridge). Not thread-safe: used from the main actor only.
public final class OnaCoreMission: MissionCore {
    private let core: OpaquePointer

    public init() {
        core = ona_core_new()
    }

    deinit {
        ona_core_free(core)
    }

    public func dispatch(_ request: [String: Any]) -> [String: Any] {
        guard let data = try? JSONSerialization.data(withJSONObject: request),
              let text = String(data: data, encoding: .utf8)
        else { return ["ok": false, "error": "request is not JSON"] }
        guard let reply = text.withCString({ ona_core_dispatch(core, $0) }) else {
            return ["ok": false, "error": "no reply from ona-core"]
        }
        defer { ona_core_string_free(reply) }
        let json = Data(bytes: reply, count: strlen(reply))
        return (try? JSONSerialization.jsonObject(with: json)) as? [String: Any]
            ?? ["ok": false, "error": "unreadable reply from ona-core"]
    }
}
