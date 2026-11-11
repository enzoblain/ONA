import Foundation
import Testing
@testable import ONA

private let oneNEAR = "1000000000000000000000000"
/// Payment digest v2 vector from the desktop apps' tests (NOTE-POUR-ENZO §7).
let paymentV2Digest = "ee00b991ccc819a4b64630c245ae7e281ef98d74f0eb971b1ff4dd9290957950"

func demoPayment(to: String = "cabinet-b.testnet", amount: String = oneNEAR, screen: String? = nil,
                 digest: String = paymentV2Digest, version: Int? = 2, nonce: String? = "00112233445566778899aabbccddeeff")
    -> PaymentRequest {
    PaymentRequest(to: to, amount: amount, screen: screen ?? "Pay \(amount) yoctoNEAR to \(to)", digest: digest,
                   digestVersion: version, network: "testnet", contract: "pay.ona.testnet", missionId: "m-1",
                   nonce: nonce)
}

@Suite("Payment check (digest v2)")
struct PaymentCheckTests {
    @Test func digestMatchesTheDesktopVector() {
        #expect(SignedFields.paymentDigest(network: "testnet", contract: "pay.ona.testnet", missionID: "m-1",
                                           nonce: "00112233445566778899aabbccddeeff", to: "cabinet-b.testnet",
                                           amount: oneNEAR) == paymentV2Digest)
    }

    @Test func acceptsTheDemoPayment() throws {
        let verified = try PaymentCheck.verify(demoPayment()).get()
        #expect(verified.digest == paymentV2Digest)
        #expect(verified.to == "cabinet-b.testnet")
        #expect(verified.amount == NEARAmount.yoctoPerNEAR)
    }

    @Test func refusesAnotherRecipientOrAmountWithTheSameDigest() {
        #expect(PaymentCheck.verify(demoPayment(to: "attacker.testnet")) == .failure(.digestMismatch))
        #expect(PaymentCheck.verify(demoPayment(amount: "2000000000000000000000000")) == .failure(.digestMismatch))
    }

    @Test func aNewNonceGivesANewDigest() {
        // The same recipient and amount, another payment: the old digest does not fit.
        #expect(PaymentCheck.verify(demoPayment(nonce: "ffeeddccbbaa99887766554433221100")) == .failure(.digestMismatch))
    }

    @Test func refusesTheOldDigestAndOtherVersions() {
        let old = "a43ba249fbdd55a64a0647282b6dff66d660a1d8a8d75a8fbf3533bfa450fa31"
        #expect(PaymentCheck.verify(demoPayment(digest: old)) == .failure(.digestMismatch))
        #expect(PaymentCheck.verify(demoPayment(version: nil)) == .failure(.unsupportedVersion))
        #expect(PaymentCheck.verify(demoPayment(version: 1)) == .failure(.unsupportedVersion))
        #expect(PaymentCheck.verify(demoPayment(nonce: nil)) == .failure(.missingField))
    }

    @Test func refusesAScreenThatSaysSomethingElse() {
        #expect(PaymentCheck.verify(demoPayment(screen: "Pay 1 NEAR to your lawyer")) == .failure(.screenMismatch))
    }

    @Test func refusesAnUnreadableAmount() {
        #expect(PaymentCheck.verify(demoPayment(amount: "1e24")) == .failure(.badAmount))
        #expect(PaymentCheck.verify(demoPayment(amount: "-1")) == .failure(.badAmount))
        #expect(PaymentCheck.verify(demoPayment(amount: "+1")) == .failure(.badAmount))
    }

    @Test(arguments: ["Cabinet-B.testnet", "cabinet\u{202e}b.testnet", "a", String(repeating: "a", count: 65),
                      "cabinet b.testnet", "саbinet-b.testnet"])
    func showsOnlyNearAccounts(to: String) {
        #expect(PaymentCheck.verify(demoPayment(to: to)) == .failure(.badAccount))
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
    @Test func decodesARecipientChoiceWithItsContent() throws {
        let json = Data("""
        {"id":"c-2","kind":"recipient","content":"5127","offers":[{"firm_id":"cabinet-b","specialties":["labour"],
          "price_cents":60000,"delay_days":10,"source_spans":["Forfait 600 euros, sous 10 jours"]}]}
        """.utf8)
        let pending = try ProtocolCoding.decoder.decode(Pending.self, from: json)
        #expect(pending.content == "5127")
        #expect(pending.request == .recipient([
            Offer(firmId: "cabinet-b", priceCents: 60000, delayDays: 10, sourceSpans: ["Forfait 600 euros, sous 10 jours"]),
        ]))
    }

    @Test func decodesAPaymentV2() throws {
        let json = Data("""
        {"id":"c-3","kind":"payment","content":"\(paymentV2Digest)","payment":{"to":"cabinet-b.testnet",
          "amount":"\(oneNEAR)","screen":"Pay \(oneNEAR) yoctoNEAR to cabinet-b.testnet","digest":"\(paymentV2Digest)",
          "digest_version":2,"network":"testnet","contract":"pay.ona.testnet","mission_id":"m-1",
          "nonce":"00112233445566778899aabbccddeeff"}}
        """.utf8)
        let pending = try ProtocolCoding.decoder.decode(Pending.self, from: json)
        guard case .payment(let payment) = pending.request else { Issue.record("payment"); return }
        #expect(payment == demoPayment())
    }

    @Test func stepsKeepTheirProtocolNames() throws {
        let steps = try ProtocolCoding.decoder.decode([Step].self, from: Data(#"["search","confirm_payment","teleport"]"#.utf8))
        #expect(steps == [.search, .confirmPayment, .unknown("teleport")])
        #expect(steps.map(\.raw) == ["search", "confirm_payment", "teleport"])
    }

    @Test func modes() throws {
        #expect(try ProtocolCoding.decoder.decode([Mode].self, from: Data(#"["mock","real","test"]"#.utf8))
                .map(\.isSimulation) == [true, false, true])
    }
}
