import Foundation
import Security

/// The only thing the app keeps across launches: which computer it is paired with, and its own key handle.
struct StoredPairing: Codable, Equatable, Sendable {
    let pairingID: String
    let name: String
    let address: URL?
    let onion: String?
    /// The computer's P-256 public key (X9.63).
    let computerKey: Data
    let keyKind: DeviceKeyKind
    /// Secure Enclave handle (encrypted, usable only on this device) or, in the simulator, the software key.
    let keyRepresentation: Data
    let pairedAt: Date
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
        return try JSONDecoder().decode(StoredPairing.self, from: data)
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
