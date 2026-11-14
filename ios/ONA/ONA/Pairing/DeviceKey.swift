import CryptoKit
import Foundation
import Security

/// The phone's signing key. On an iPhone it lives in the Secure Enclave and every signature asks for Face ID / the
/// passcode; the private key never leaves the chip.
protocol DeviceKey: Sendable {
    var kind: DeviceKeyKind { get }
    /// P-256 public key, X9.63 uncompressed (65 bytes).
    var publicKey: Data { get }
    /// What to keep in the Keychain to load the key again (Secure Enclave: an encrypted handle usable only on this
    /// device; software: the raw key, simulator and tests only).
    var storedRepresentation: Data { get }
    /// ECDSA P-256 / SHA-256 signature, DER, low-s (the computer refuses high-s). May block while the system asks for
    /// Face ID or the passcode: never call on the main thread.
    func sign(_ message: Data) throws -> Data
}

enum DeviceKeyKind: String, Codable, Sendable {
    case secureEnclave
    /// No Secure Enclave (simulator, Mac tests). Shown as such in the app.
    case software
}

enum DeviceKeyError: LocalizedError {
    case secureEnclaveUnavailable
    case accessControl
    case unreadableKey

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable: "This device has no usable Secure Enclave."
        case .accessControl: "Could not protect the key with Face ID or the passcode."
        case .unreadableKey: "This device's key cannot be read: pair again."
        }
    }
}

struct SecureEnclaveDeviceKey: DeviceKey {
    let key: SecureEnclave.P256.Signing.PrivateKey

    var kind: DeviceKeyKind { .secureEnclave }
    var publicKey: Data { key.publicKey.x963Representation }
    var storedRepresentation: Data { key.dataRepresentation }

    func sign(_ message: Data) throws -> Data {
        try SignedFields.lowS(key.signature(for: message)).derRepresentation
    }

    /// New key, usable only when the device is unlocked, only on this device, and only after Face ID or the passcode.
    static func create() throws -> SecureEnclaveDeviceKey {
        guard SecureEnclave.isAvailable else { throw DeviceKeyError.secureEnclaveUnavailable }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error
        ) else { throw DeviceKeyError.accessControl }
        return SecureEnclaveDeviceKey(key: try SecureEnclave.P256.Signing.PrivateKey(accessControl: access))
    }
}

struct SoftwareDeviceKey: DeviceKey {
    let key: P256.Signing.PrivateKey

    init(key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.key = key
    }

    var kind: DeviceKeyKind { .software }
    var publicKey: Data { key.publicKey.x963Representation }
    var storedRepresentation: Data { key.rawRepresentation }

    func sign(_ message: Data) throws -> Data {
        try SignedFields.lowS(key.signature(for: message)).derRepresentation
    }
}

enum DeviceKeys {
    /// A Secure Enclave key; a software key only where there is no Secure Enclave by design (the iOS simulator).
    static func create() throws -> any DeviceKey {
        #if targetEnvironment(simulator)
        return SoftwareDeviceKey()
        #else
        return try SecureEnclaveDeviceKey.create()
        #endif
    }

    static func load(kind: DeviceKeyKind, representation: Data) throws -> any DeviceKey {
        switch kind {
        case .secureEnclave:
            guard let key = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: representation) else {
                throw DeviceKeyError.unreadableKey
            }
            return SecureEnclaveDeviceKey(key: key)
        case .software:
            // A software key exists only where there is no Secure Enclave by design: never accept one on an iPhone.
            #if os(iOS) && !targetEnvironment(simulator)
            throw DeviceKeyError.unreadableKey
            #else
            guard let key = try? P256.Signing.PrivateKey(rawRepresentation: representation) else {
                throw DeviceKeyError.unreadableKey
            }
            return SoftwareDeviceKey(key: key)
            #endif
        }
    }
}
