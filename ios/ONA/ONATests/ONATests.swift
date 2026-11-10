import Foundation
import Testing
@testable import ONA

// Digest printed by ona-core's `ona demo` (branch main, 2026-11-10) for 1 NEAR to cabinet-b.testnet.
private let onaCoreDemoDigest = "a43ba249fbdd55a64a0647282b6dff66d660a1d8a8d75a8fbf3533bfa450fa31"
private let oneNEAR = "1000000000000000000000000"

private func demoPayment(to: String = "cabinet-b.testnet", amount: String = oneNEAR,
                         screen: String? = nil, digest: String = onaCoreDemoDigest) -> PaymentRequest {
    PaymentRequest(to: to, amount: amount, screen: screen ?? "Pay \(amount) yoctoNEAR to \(to)", digest: digest)
}

@Suite("Payment check")
struct PaymentCheckTests {
    @Test func digestMatchesOnaCore() {
        #expect(PaymentCheck.digest(to: "cabinet-b.testnet", amount: NEARAmount.yoctoPerNEAR) == onaCoreDemoDigest)
    }

    @Test func byteLayout() {
        let bytes = PaymentCheck.bytes(to: "ab", amount: 1)
        #expect(Array(bytes) == [2, 0, 0, 0, 0x61, 0x62, 1] + Array(repeating: 0, count: 15))
    }

    @Test func acceptsTheDemoPayment() throws {
        let verified = try PaymentCheck.verify(demoPayment()).get()
        #expect(verified.digest == onaCoreDemoDigest)
        #expect(verified.to == "cabinet-b.testnet")
    }

    @Test func refusesAnotherRecipientWithTheSameDigest() {
        #expect(PaymentCheck.verify(demoPayment(to: "attacker.testnet")) == .failure(.digestMismatch))
    }

    @Test func refusesAnotherAmountWithTheSameDigest() {
        #expect(PaymentCheck.verify(demoPayment(amount: "2000000000000000000000000")) == .failure(.digestMismatch))
    }

    @Test func refusesAScreenThatSaysSomethingElse() {
        let request = demoPayment(screen: "Pay 1 NEAR to your lawyer")
        #expect(PaymentCheck.verify(request) == .failure(.screenMismatch))
    }

    @Test func refusesAnUnreadableAmount() {
        #expect(PaymentCheck.verify(demoPayment(amount: "1e24")) == .failure(.badAmount))
        #expect(PaymentCheck.verify(demoPayment(amount: "-1")) == .failure(.badAmount))
    }

    @Test(arguments: [
        ("1000000000000000000000000", "1"),
        ("500000000000000000000000", "0.5"),
        ("1", "0.000000000000000000000001"),
        ("12000001000000000000000000", "12.000001"),
        ("0", "0"),
    ])
    func formatsNEAR(yocto: String, expected: String) throws {
        let amount = try #require(UInt128(yocto, radix: 10))
        #expect(NEARAmount.format(amount) == expected)
    }
}

@Suite("Messages")
struct MessageTests {
    static let waitingForPayment = Data("""
    {"mode":"mock","computer":{"name":"Ordinateur simulé"},
     "mission":{"id":"m-1","title":"Trouver un avocat","phase":"waiting",
       "steps":[{"step":"search","status":"done"},{"step":"confirm_payment","status":"current"},
                {"step":"teleport","status":"pending"}],
       "events":[{"at":1762790000,"text":"En attente"}],
       "pending":{"id":"c-3","kind":"payment","payment":{"to":"cabinet-b.testnet","amount":"\(oneNEAR)",
         "screen":"Pay \(oneNEAR) yoctoNEAR to cabinet-b.testnet","digest":"\(onaCoreDemoDigest)"}},
       "exposure":null}}
    """.utf8)

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(type, from: data)
    }

    @Test func decodesAPaymentConfirmation() throws {
        let state = try decode(ComputerState.self, Self.waitingForPayment)
        #expect(state.isSimulation)
        let mission = try #require(state.mission)
        #expect(mission.phase == .waiting)
        #expect(mission.steps.map(\.step) == [.search, .confirmPayment, .unknown("teleport")])
        let pending = try #require(mission.pending)
        guard case .payment(let payment) = pending.request else {
            Issue.record("expected a payment")
            return
        }
        #expect(payment.digest == onaCoreDemoDigest)
    }

    @Test func decodesARecipientChoice() throws {
        let json = Data("""
        {"id":"c-2","kind":"recipient","offers":[{"firm_id":"cabinet-b","specialties":["labour"],
          "price_cents":60000,"delay_days":10,"source_spans":["Forfait 600 euros, sous 10 jours"]}]}
        """.utf8)
        let pending = try decode(Pending.self, json)
        #expect(pending.request == .recipient([
            Offer(firmId: "cabinet-b", priceCents: 60000, delayDays: 10, sourceSpans: ["Forfait 600 euros, sous 10 jours"]),
        ]))
    }

    @Test func realModeIsNotASimulation() throws {
        let state = try decode(ComputerState.self, Data(#"{"mode":"real","computer":{"name":"Mac"},"mission":null}"#.utf8))
        #expect(!state.isSimulation)
    }

    @Test func unknownModeCountsAsSimulation() throws {
        let state = try decode(ComputerState.self, Data(#"{"mode":"test","computer":{"name":"Mac"},"mission":null}"#.utf8))
        #expect(state.isSimulation)
    }

    @Test func confirmationEncodesSnakeCaseFieldsOnly() throws {
        var body = ConfirmationAnswer(id: "c-3", decision: .accept, digest: "ab")
        body.pairingId = "p-1"
        let object = try JSONSerialization.jsonObject(with: ProtocolCoding.encoder.encode(body)) as? [String: Any]
        #expect(object?["id"] as? String == "c-3")
        #expect(object?["decision"] as? String == "accept")
        #expect(object?["digest"] as? String == "ab")
        #expect(object?["pairing_id"] as? String == "p-1")
        #expect(object?["firm"] == nil)
    }
}
