import Foundation

/// The real model: ona-core's planner and page reader call NEAR AI through the relay, and every connection the core
/// opens goes through this app's tor (docs/desktop/app.md, "Real model").
///
/// It is chosen by `~/Library/Application Support/ONA/model.json`, with the names of `ona real` (docs/INSTALL.md):
/// `relay_url`, `model`, `max_tokens`, `token_budget` (for each conversation) and `tokens_file`. Without the file the
/// core keeps its fake model and the app shows the simulation banner. With it, a core is real or refuses every command
/// with the reason: never a silent fake. The NEAR AI key is not here: the relay holds it.
public enum RealModel {
    public static var file: URL {
        URL.applicationSupportDirectory.appending(path: "ONA/model.json")
    }

    /// The settings handed to `ona_core_new_with`, as JSON text.
    public static func setup(file: URL = file, coreSocks: UInt16?) -> String {
        var setup: [String: Any] = ["model": NSNull(), "core_socks": coreSocks.map { Int($0) } ?? NSNull()]
        do {
            let data = try Data(contentsOf: file)
            guard let model = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw CocoaError(.fileReadCorruptFile)
            }
            setup["model"] = model
        } catch CocoaError.fileReadNoSuchFile {
            // No file: the fake model.
        } catch {
            setup = ["error": "model.json : \(error.localizedDescription)"]
        }
        let data = (try? JSONSerialization.data(withJSONObject: setup)) ?? Data(#"{"error":"model.json"}"#.utf8)
        return String(decoding: data, as: UTF8.self)
    }
}
