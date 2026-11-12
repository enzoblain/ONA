import Foundation

/// The real model: ona-core's planner and page reader call NEAR AI through the relay, and every connection the core
/// opens goes through this app's tor (docs/desktop/app.md, "Real model").
///
/// It is chosen by `~/Library/Application Support/ONA/model.json`, with the names of `ona real` (docs/INSTALL.md):
/// `relay_url`, `model`, `max_tokens`, `token_budget` (for each conversation) and `tokens_file`. Without the file the
/// core keeps its fake model and the app shows the simulation banner. With it, a core is real or refuses every command
/// with the reason: never a silent fake. The NEAR AI key is not here: the relay holds it.
///
/// The pool wallet is chosen the same way by `pool.json` (docs/desktop/app.md, "Pool").
public enum RealModel {
    public static var file: URL {
        URL.applicationSupportDirectory.appending(path: "ONA/model.json")
    }

    /// `pool.json`: `wallet_file`, `wallet_key_file`, `pool`, `rpc_url`, and optionally `rpc_url_2`,
    /// `recommended_near`, `agent_url` (the names of `ona`'s `ONA_WALLET_FILE`… variables).
    public static var poolFile: URL {
        URL.applicationSupportDirectory.appending(path: "ONA/pool.json")
    }

    /// The settings handed to `ona_core_new_with`, as JSON text.
    public static func setup(file: URL = file, coreSocks: UInt16?) -> String {
        settings(file: file, key: "model", base: ["model": NSNull()], coreSocks: coreSocks)
    }

    /// The settings of the app's pool core, as JSON text: `{"model": null, "pool": <pool.json or null>, "core_socks"}`,
    /// or `{"error": …}` when `pool.json` cannot be read. Without the file the core answers `no pool wallet configured`.
    public static func poolSetup(file: URL = poolFile, coreSocks: UInt16?) -> String {
        settings(file: file, key: "pool", base: ["model": NSNull(), "pool": NSNull()], coreSocks: coreSocks)
    }

    /// `base` with `key` set to the file's object; unchanged without the file; `{"error"}` when it cannot be read.
    private static func settings(file: URL, key: String, base: [String: Any], coreSocks: UInt16?) -> String {
        var setup = base
        setup["core_socks"] = coreSocks.map { Int($0) } ?? NSNull()
        let name = file.lastPathComponent
        do {
            let data = try Data(contentsOf: file)
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw CocoaError(.fileReadCorruptFile)
            }
            setup[key] = object
        } catch CocoaError.fileReadNoSuchFile {
            // No file: the fake model, or no pool wallet.
        } catch {
            setup = ["error": "\(name) : \(error.localizedDescription)"]
        }
        let data = (try? JSONSerialization.data(withJSONObject: setup)) ?? Data(#"{"error":"settings"}"#.utf8)
        return String(decoding: data, as: UTF8.self)
    }
}
