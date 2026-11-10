import CryptoKit
import Foundation
import Observation
import Security

/// What the computer keeps about pairing: its own key, and the phone it trusts.
public struct PairingRecord: Codable, Equatable, Sendable {
    /// The computer's P-256 private key (raw). Identifies this computer to the phone (6-digit code).
    public var computerKey: Data
    public var phone: PairedPhone?

    public struct PairedPhone: Codable, Equatable, Sendable {
        public let pairingID: String
        /// The phone's P-256 public key (X9.63): every signed request must verify with it.
        public let phoneKey: Data
        public let pairedAt: Date
        /// False until the person confirms on the computer that both screens show the same code.
        public var verified: Bool
    }
}

public protocol PairingStore: Sendable {
    func load() throws -> PairingRecord?
    func save(_ record: PairingRecord) throws
}

/// One item in the user's login keychain (the app is not sandboxed and has no keychain entitlement, so it uses the
/// file-based keychain of this Mac).
public struct KeychainPairingStore: PairingStore {
    let service = "org.ona.desktop.pairing"
    let account = "phone"

    public init() {}

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    public func load() throws -> PairingRecord? {
        var request = query
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return try JSONDecoder().decode(PairingRecord.self, from: data)
    }

    public func save(_ record: PairingRecord) throws {
        SecItemDelete(query as CFDictionary)
        var item = query
        item[kSecValueData as String] = try JSONEncoder().encode(record)
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }
}

public final class MemoryPairingStore: PairingStore, @unchecked Sendable {
    private let lock = NSLock()
    private var record: PairingRecord?
    public init(_ record: PairingRecord? = nil) { self.record = record }
    public func load() throws -> PairingRecord? { lock.withLock { record } }
    public func save(_ record: PairingRecord) throws { lock.withLock { self.record = record } }
}

/// Pairing on the computer side: the QR code, the phone's proof of key, the 6-digit code, and the signature checks
/// on every request from the phone.
@MainActor
@Observable
public final class PairingAuthority {
    /// A phone that just paired, waiting for the person to compare the codes.
    public struct Awaiting: Equatable, Sendable {
        public let code: String
        public let pairingID: String
    }

    public let name: String
    public private(set) var record: PairingRecord
    /// Single-use code currently in the QR; nil once used.
    public private(set) var pairingCode: String?
    public private(set) var awaiting: Awaiting?

    private let store: any PairingStore
    private var count = 0

    public init(name: String, store: any PairingStore) {
        self.name = name
        self.store = store
        if let saved = try? store.load() {
            record = saved
        } else {
            record = PairingRecord(computerKey: P256.Signing.PrivateKey().rawRepresentation, phone: nil)
            try? store.save(record)
        }
        if record.phone == nil { newCode() }
    }

    public var computerPublicKey: Data {
        ((try? P256.Signing.PrivateKey(rawRepresentation: record.computerKey))?.publicKey.x963Representation) ?? Data()
    }

    public var isPaired: Bool { record.phone?.verified == true }

    /// The QR text for a given address (local network) or onion address (Tor).
    public func payload(address: String?, onion: String?) -> String? {
        guard let pairingCode else { return nil }
        return ProtocolBytes.pairingPayload(name: name, address: address, onion: onion,
                                            computerKey: computerPublicKey, code: pairingCode)
    }

    /// `POST /v0/pair`. Returns the pairing id, or a protocol error code.
    public func pair(code: String?, phoneKeyBase64: String?, signature: String?) -> Result<String, ProtocolError> {
        guard let pairingCode, code == pairingCode else { return .failure(.usedCode) }
        guard let phoneKeyBase64, let phoneKey = Data(base64Encoded: phoneKeyBase64),
              (try? P256.Signing.PublicKey(x963Representation: phoneKey)) != nil
        else { return .failure(.badSignature) }
        let message = ProtocolBytes.pairMessage(code: pairingCode, phoneKey: phoneKey, computerKey: computerPublicKey)
        guard ProtocolBytes.verify(signature: signature, of: message, by: phoneKey) else {
            return .failure(.pairingSignature)
        }
        self.pairingCode = nil  // single use
        count += 1
        let id = "p-\(count)-" + ProtocolBytes.base64URL(Data((0..<6).map { _ in UInt8.random(in: 0...255) }))
        record.phone = .init(pairingID: id, phoneKey: phoneKey, pairedAt: .now, verified: false)
        try? store.save(record)
        awaiting = Awaiting(
            code: ProtocolBytes.verificationCode(computerKey: computerPublicKey, phoneKey: phoneKey, code: pairingCode),
            pairingID: id
        )
        return .success(id)
    }

    /// The person saw the same code on both screens.
    public func confirmCode() {
        guard var phone = record.phone, phone.pairingID == awaiting?.pairingID else { return }
        phone.verified = true
        record.phone = phone
        try? store.save(record)
        awaiting = nil
    }

    /// The codes differ, or the person forgets the phone: a new QR code is issued.
    public func forgetPhone() {
        record.phone = nil
        awaiting = nil
        try? store.save(record)
        newCode()
    }

    /// Checks that a request was signed by the paired, verified phone.
    public func check(pairingID: String?, signature: String?, signed: (String) -> Data) -> ProtocolError? {
        guard let phone = record.phone else { return .notPaired }
        guard pairingID == phone.pairingID else { return .unknownPairing }
        guard phone.verified else { return .notVerified }
        guard signature != nil else { return .missingSignature }
        guard ProtocolBytes.verify(signature: signature, of: signed(phone.pairingID), by: phone.phoneKey) else {
            return .badSignature
        }
        return nil
    }

    private func newCode() {
        pairingCode = ProtocolBytes.base64URL(Data((0..<16).map { _ in UInt8.random(in: 0...255) }))
    }
}

/// Error codes sent back to the phone (the iPhone app translates them).
public enum ProtocolError: String, Error, Sendable {
    case usedCode = "unknown or used pairing code"
    case pairingSignature = "pairing signature does not verify"
    case notPaired = "not paired"
    case unknownPairing = "unknown pairing"
    case notVerified = "pairing not verified"
    case missingSignature = "missing or malformed signature"
    case badSignature = "signature does not verify"
    case stale = "stale confirmation"
    case unknownChat = "unknown chat"
    case badText = "empty or too long message"
    case badRequest = "bad request"
}
