import Foundation
import Security

/// The only thing the app keeps across launches: which computer it is paired with, its own key handle, the read
/// token and the write counter (protocol v1). Saved only after the person compared the 6-digit codes.
struct StoredPairing: Codable, Equatable, Sendable {
    let pairingID: String
    let name: String
    let address: URL?
    let onion: String?
    /// The Tor client authorization key for `onion` (32 bytes), from the QR code. Absent for a pairing made before it
    /// existed, or on the local network.
    var onionAuth: Data? = nil
    /// The computer's P-256 public key (X9.63).
    let computerKey: Data
    let keyKind: DeviceKeyKind
    /// Secure Enclave handle (encrypted, usable only on this device) or, in the simulator, the software key.
    let keyRepresentation: Data
    let pairedAt: Date
    /// Given by the computer at pairing: needed for every request. Sent only inside the Tor stream.
    let token: String
    /// Last counter used by a write. Only goes up, never reused (even after a network error or a refusal).
    var counter: UInt64
}

protocol PairingStore: Sendable {
    func load() throws -> StoredPairing?
    func save(_ pairing: StoredPairing) throws
    func delete() throws
}

enum PairingStoreError: LocalizedError {
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .keychain(let status): "Trousseau : erreur \(status)"
        }
    }
}

/// One Keychain item: readable only while the device is unlocked, this device only, never synced to iCloud.
struct KeychainPairingStore: PairingStore {
    let service = "org.ona.remote.pairing"
    let account = "computer"

    private var query: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
        ]
    }

    func load() throws -> StoredPairing? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw PairingStoreError.keychain(status) }
        guard let pairing = try? JSONDecoder().decode(StoredPairing.self, from: data) else {
            // A pairing from protocol v0 (no token, no counter) cannot be used with v1 computers: pair again.
            try delete()
            return nil
        }
        return pairing
    }

    func save(_ pairing: StoredPairing) throws {
        try delete()
        var item = query
        item[kSecValueData as String] = try JSONEncoder().encode(pairing)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw PairingStoreError.keychain(status) }
    }

    func delete() throws {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw PairingStoreError.keychain(status) }
    }
}

/// For tests and previews.
final class MemoryPairingStore: PairingStore, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: StoredPairing?

    init(_ pairing: StoredPairing? = nil) { stored = pairing }

    func load() throws -> StoredPairing? { lock.withLock { stored } }
    func save(_ pairing: StoredPairing) throws { lock.withLock { stored = pairing } }
    func delete() throws { lock.withLock { stored = nil } }
}
