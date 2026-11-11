import CryptoKit
import Foundation
import Observation
import Security

/// What the computer keeps about pairing: its own key, and the phone it trusts.
public struct PairingRecord: Codable, Equatable, Sendable {
    /// The computer's P-256 private key (raw). Signs every reply to the phone, which knows the public key (QR).
    public var computerKey: Data
    public var phone: PairedPhone?

    public struct PairedPhone: Codable, Equatable, Sendable {
        public let pairingID: String
        /// The phone's P-256 public key (X9.63): every signed request must verify with it.
        public let phoneKey: Data
        public let pairedAt: Date
        /// Always true for a phone saved by this version (saved only after the codes were compared). An unverified
        /// phone saved by an earlier version is dropped when loading.
        public var verified: Bool
        /// Secret given to the phone at pairing (base64url, 32 bytes): every request carries it.
        public var token: String
        /// Highest request counter accepted from this phone, saved before the request is carried out.
        public var lastCounter: UInt64
        /// Confirmation ids already answered by this phone, most recent last.
        public var usedConfirmations: [String]

        public init(pairingID: String, phoneKey: Data, pairedAt: Date, token: String) {
            self.pairingID = pairingID
            self.phoneKey = phoneKey
            self.pairedAt = pairedAt
            verified = true
            self.token = token
            lastCounter = 0
            usedConfirmations = []
        }

        public init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            pairingID = try c.decode(String.self, forKey: .pairingID)
            phoneKey = try c.decode(Data.self, forKey: .phoneKey)
            pairedAt = try c.decode(Date.self, forKey: .pairedAt)
            verified = try c.decodeIfPresent(Bool.self, forKey: .verified) ?? false
            token = try c.decodeIfPresent(String.self, forKey: .token) ?? ""
            lastCounter = try c.decodeIfPresent(UInt64.self, forKey: .lastCounter) ?? 0
            usedConfirmations = try c.decodeIfPresent([String].self, forKey: .usedConfirmations) ?? []
        }
    }
}

public protocol PairingStore: Sendable {
    func load() throws -> PairingRecord?
    func save(_ record: PairingRecord) throws
}

/// One item in the user's login keychain (the app is not sandboxed and has no keychain entitlement, so it uses the
/// file-based keychain of this Mac). Readable only while the Mac is unlocked, never synchronised.
public struct KeychainPairingStore: PairingStore {
    let service = "org.ona.desktop.pairing"
    let account = "phone"

    public init() {}

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    /// Attributes of a new item: data, and its access class.
    static func attributes(_ data: Data) -> [String: Any] {
        [kSecValueData as String: data,
         kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly]
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

    /// Updates the item in place (no window where it is absent), or adds it.
    public func save(_ record: PairingRecord) throws {
        let data = try JSONEncoder().encode(record)
        var status = SecItemUpdate(query as CFDictionary, Self.attributes(data) as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(query.merging(Self.attributes(data)) { $1 } as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
    }
}

public final class MemoryPairingStore: PairingStore, @unchecked Sendable {
    private let lock = NSLock()
    private var record: PairingRecord?
    /// Tests: makes `save` fail.
    public var failing = false
    /// Tests: makes `load` fail (a record that exists but cannot be read).
    public var unreadable = false
    public init(_ record: PairingRecord? = nil) { self.record = record }
    public func load() throws -> PairingRecord? {
        try lock.withLock {
            if unreadable { throw CocoaError(.fileReadCorruptFile) }
            return record
        }
    }
    public func save(_ record: PairingRecord) throws {
        try lock.withLock {
            if failing { throw CocoaError(.fileWriteNoPermission) }
            self.record = record
        }
    }
}

/// Pairing on the computer side: the QR code, the phone's commitment then reveal, the 6-digit code, the token, and
/// the checks on every request from the phone (signature, counter, used confirmation ids).
@MainActor
@Observable
public final class PairingAuthority {
    /// A phone that revealed its key, waiting for the person to compare the codes. In memory only.
    public struct Awaiting: Equatable, Sendable {
        public let code: String
        public let pairingID: String
        let phone: PairingRecord.PairedPhone
        /// When the phone revealed its key: the comparison must be done within `awaitLifetime`.
        var at: Date
    }

    public struct Code: Equatable, Sendable {
        public let value: String
        public internal(set) var issuedAt: Date
    }

    struct Commit: Equatable {
        let pairingID: String
        let commitment: String
        let computerNonce: String
        let code: String
        var at: Date
    }

    public static let codeLifetime: TimeInterval = 600
    public static let commitLifetime: TimeInterval = 120
    public static let awaitLifetime: TimeInterval = 300
    public static let maxFailedCodes = 5
    public static let maxUsedIDs = 256

    public let name: String
    public private(set) var record: PairingRecord
    /// Single-use code currently in the QR; nil once used or while a phone is paired.
    public internal(set) var pairingCode: Code?
    public internal(set) var awaiting: Awaiting?
    /// Last failure to save the record, shown in the window.
    public private(set) var storageError: String?
    var commit: Commit?
    private var failedCodes = 0
    /// Set when the record exists but cannot be read: pairing is disabled and nothing is saved.
    private var unreadable: String?

    private let store: any PairingStore

    public init(name: String, store: any PairingStore) {
        self.name = name
        self.store = store
        var created = false
        do {
            if let saved = try store.load() {
                record = saved
            } else {
                record = PairingRecord(computerKey: P256.Signing.PrivateKey().rawRepresentation, phone: nil)
                created = true
            }
        } catch {
            // The record exists but cannot be read: show it, write nothing, offer no QR code (a new key would
            // silently replace this computer's identity and forget the phone).
            record = PairingRecord(computerKey: P256.Signing.PrivateKey().rawRepresentation, phone: nil)
            unreadable = "Appairage illisible (\(error.localizedDescription)) : rien n'a été modifié."
            storageError = unreadable
            return
        }
        // A phone from an earlier version (not verified, or without token) must pair again.
        if let phone = record.phone, !phone.verified || phone.token.isEmpty || phone.phoneKey.count != 65 {
            record.phone = nil
            created = true
        }
        if created { _ = save() }
        if record.phone == nil { newCode() }
    }

    private var signingKey: P256.Signing.PrivateKey? {
        try? P256.Signing.PrivateKey(rawRepresentation: record.computerKey)
    }

    public var computerPublicKey: Data { signingKey?.publicKey.x963Representation ?? Data() }

    public var isPaired: Bool { record.phone != nil }

    /// Signs a reply to the phone with the computer's key.
    public func signReply(nonce: String, method: String, path: String, status: Int, reply: Data) -> String? {
        guard let signingKey else { return nil }
        return ProtocolBytes.sign(ProtocolBytes.replyMessage(nonce: nonce, method: method, path: path, status: status,
                                                             reply: reply), with: signingKey)
    }

    /// The QR text for a given address (local network) or onion address (Tor), while the code is valid.
    public func payload(address: String?, onion: String?) -> String? {
        guard let pairingCode, Date.now < pairingCode.issuedAt + Self.codeLifetime else { return nil }
        return ProtocolBytes.pairingPayload(name: name, address: address, onion: onion, computerKey: computerPublicKey,
                                            code: pairingCode.value,
                                            expiresAt: Int((pairingCode.issuedAt + Self.codeLifetime).timeIntervalSince1970))
    }

    /// Replaces an expired code and drops a commitment never revealed. Called on a timer.
    public func tick() {
        if let pairingCode, Date.now >= pairingCode.issuedAt + Self.codeLifetime { newCode() }
        if let commit, Date.now >= commit.at + Self.commitLifetime {
            self.commit = nil
            newCode()
        }
        if let awaiting, Date.now >= awaiting.at + Self.awaitLifetime {
            self.awaiting = nil
            newCode()
        }
    }

    /// `POST /v1/pair`: the QR code and the phone's commitment. The code is used up. Returns (pairing id, nonce).
    public func commit(code: String?, commitment: String?) -> Result<(String, String), ProtocolError> {
        guard let current = pairingCode else { return .failure(.usedCode) }
        guard Date.now < current.issuedAt + Self.codeLifetime else {
            newCode()
            return .failure(.expiredCode)
        }
        guard ProtocolBytes.sameSecret(code ?? "", current.value) else {
            failedCodes += 1
            if failedCodes >= Self.maxFailedCodes { newCode() }
            return .failure(.usedCode)
        }
        guard let commitment, ProtocolBytes.isHex(commitment, length: 64) else { return .failure(.badRequest) }
        pairingCode = nil  // single use, whatever happens next
        let commit = Commit(pairingID: "p-" + ProtocolBytes.randomHex16(), commitment: commitment,
                            computerNonce: ProtocolBytes.randomHex16(), code: current.value, at: .now)
        self.commit = commit
        return .success((commit.pairingID, commit.computerNonce))
    }

    /// `POST /v1/pair/reveal`: one attempt per commitment; on failure a new code is issued. Returns (pairing id,
    /// token). The phone stays in memory until the person confirms the codes.
    public func reveal(pairingID: String?, phoneKeyBase64: String?, phoneNonce: String?, signature: String?)
        -> Result<(String, String), ProtocolError> {
        guard let commit, commit.pairingID == pairingID, Date.now < commit.at + Self.commitLifetime else {
            return .failure(.unknownPairing)
        }
        self.commit = nil
        let result = checkReveal(commit, phoneKeyBase64, phoneNonce, signature)
        if case .failure = result { newCode() }
        return result
    }

    private func checkReveal(_ commit: Commit, _ phoneKeyBase64: String?, _ phoneNonce: String?, _ signature: String?)
        -> Result<(String, String), ProtocolError> {
        guard let phoneNonce, ProtocolBytes.isHex(phoneNonce, length: 32),
              let phoneKeyBase64, let phoneKey = Data(base64Encoded: phoneKeyBase64), phoneKey.count == 65,
              (try? P256.Signing.PublicKey(x963Representation: phoneKey)) != nil
        else { return .failure(.badRequest) }
        guard ProtocolBytes.commitment(phoneKey: phoneKey, phoneNonce: phoneNonce) == commit.commitment else {
            return .failure(.commitmentMismatch)
        }
        let message = ProtocolBytes.pairMessage(pairingID: commit.pairingID, code: commit.code, phoneKey: phoneKey,
                                                computerKey: computerPublicKey, phoneNonce: phoneNonce,
                                                computerNonce: commit.computerNonce)
        guard ProtocolBytes.verify(signature: signature, of: message, by: phoneKey) else {
            return .failure(.pairingSignature)
        }
        var generator = SystemRandomNumberGenerator()
        let token = ProtocolBytes.base64URL(Data((0..<32).map { _ in UInt8.random(in: 0...255, using: &generator) }))
        let code = ProtocolBytes.verificationCode(computerKey: computerPublicKey, phoneKey: phoneKey, code: commit.code,
                                                  phoneNonce: phoneNonce, computerNonce: commit.computerNonce)
        awaiting = Awaiting(code: code, pairingID: commit.pairingID,
                            phone: .init(pairingID: commit.pairingID, phoneKey: phoneKey, pairedAt: .now, token: token),
                            at: .now)
        return .success((commit.pairingID, token))
    }

    /// The person saw the same code on both screens: the phone is trusted and saved. False if it could not be saved.
    @discardableResult
    public func confirmCode() -> Bool {
        guard let awaiting else { return true }
        self.awaiting = nil
        guard Date.now < awaiting.at + Self.awaitLifetime else {
            newCode()  // too late: the person starts again with the new QR code
            return false
        }
        record.phone = awaiting.phone
        return save()
    }

    /// The codes differ, or the person forgets the phone: a new QR code is issued. False if it could not be saved
    /// (the window shows `storageError`: the phone would be trusted again after a restart).
    @discardableResult
    public func forgetPhone() -> Bool {
        record.phone = nil
        awaiting = nil
        commit = nil
        newCode()
        return save()
    }

    /// Every request after pairing carries the token. Reads need nothing else.
    public func authorize(token: String?) -> ProtocolError? {
        guard let phone = record.phone else { return .notPaired }
        return ProtocolBytes.sameSecret(token ?? "", phone.token) ? nil : .badToken
    }

    /// A request that changes something: token, pairing id, the phone's signature over bytes that include `counter`,
    /// a counter higher than any accepted before, a confirmation id never answered. Saved before it is carried out.
    public func check(token: String?, pairingID: String?, counter: UInt64?, signature: String?,
                      confirmation: String? = nil, signed: (String, UInt64) -> Data) -> ProtocolError? {
        if let failure = authorize(token: token) { return failure }
        guard var phone = record.phone else { return .notPaired }
        guard pairingID == phone.pairingID else { return .unknownPairing }
        guard let counter, signature != nil else { return .missingSignature }
        guard ProtocolBytes.verify(signature: signature, of: signed(phone.pairingID, counter), by: phone.phoneKey) else {
            return .badSignature
        }
        guard counter > phone.lastCounter else { return .replayed }
        if let confirmation, phone.usedConfirmations.contains(confirmation) { return .replayed }
        phone.lastCounter = counter
        record.phone = phone
        return save() ? nil : .storage
    }

    /// A confirmation the computer carried out: its id is never accepted again. Called only after success, so a
    /// refused answer (the counter already stops its replay) does not block the next one. A failed save is shown.
    public func recordConfirmation(_ id: String) {
        guard var phone = record.phone else { return }
        phone.usedConfirmations.append(id)
        phone.usedConfirmations.removeFirst(max(0, phone.usedConfirmations.count - Self.maxUsedIDs))
        record.phone = phone
        _ = save()
    }

    private func newCode() {
        guard unreadable == nil else {
            pairingCode = nil  // no pairing until the record can be read
            return
        }
        var generator = SystemRandomNumberGenerator()
        pairingCode = Code(value: ProtocolBytes.base64URL(Data((0..<16).map { _ in
            UInt8.random(in: 0...255, using: &generator)
        })), issuedAt: .now)
        failedCodes = 0
    }

    private func save() -> Bool {
        if let unreadable {
            storageError = unreadable
            return false
        }
        do {
            try store.save(record)
            storageError = nil
            return true
        } catch {
            storageError = "Enregistrement de l'appairage impossible : \(error.localizedDescription)"
            return false
        }
    }
}

/// Error codes sent back to the phone (the iPhone app translates them).
public enum ProtocolError: String, Error, Sendable {
    case usedCode = "unknown or used pairing code"
    case expiredCode = "expired pairing code"
    case commitmentMismatch = "pairing commitment does not match"
    case pairingSignature = "pairing signature does not verify"
    case notPaired = "not paired"
    case unknownPairing = "unknown pairing"
    case missingSignature = "missing or malformed signature"
    case badSignature = "signature does not verify"
    case badToken = "missing or wrong token"
    case replayed = "replayed request"
    case storage = "could not save on the computer"
    case stale = "stale confirmation"
    case unknownChat = "unknown chat"
    case badText = "empty or too long message"
    case badRequest = "bad request"
    case badHost = "unexpected host"
    case browser = "browser requests are refused"
}
