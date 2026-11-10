"""Tests of the fake computer. Run: python3 -m unittest -v (from this folder)."""

import unittest

import mock_computer as mc

# Digest printed by ona-core's `ona demo` (branch main) for 1 NEAR to cabinet-b.testnet.
ONA_CORE_DEMO_DIGEST = "a43ba249fbdd55a64a0647282b6dff66d660a1d8a8d75a8fbf3533bfa450fa31"


def run_until_waiting(mission: mc.Mission, limit: int = 50) -> None:
    for _ in range(limit):
        if mission.phase != "running":
            return
        mission.tick()
    raise AssertionError("mission never stopped")


class PaymentBytes(unittest.TestCase):
    def test_digest_matches_ona_core_demo(self):
        self.assertEqual(mc.payment_digest("cabinet-b.testnet", mc.DEMO_AMOUNT), ONA_CORE_DEMO_DIGEST)

    def test_layout(self):
        raw = mc.payment_bytes("ab", 1)
        self.assertEqual(raw, b"\x02\x00\x00\x00ab\x01" + b"\x00" * 15)


class MissionFlow(unittest.TestCase):
    def test_full_mission(self):
        m = mc.Mission(1)
        self.assertEqual(m.pending["kind"], "plan")
        self.assertIsNone(m.confirm({"id": m.pending["id"], "decision": "accept"}))

        run_until_waiting(m)
        self.assertEqual(m.pending["kind"], "recipient")
        self.assertEqual([o["firm_id"] for o in m.pending["offers"]], ["cabinet-a", "cabinet-b"])
        self.assertIsNone(m.confirm({"id": m.pending["id"], "decision": "accept", "firm": "cabinet-b"}))

        run_until_waiting(m)
        self.assertEqual(m.pending["kind"], "payment")
        payment = m.pending["payment"]
        self.assertEqual(payment["to"], "cabinet-b.testnet")
        self.assertIsNone(m.confirm({"id": m.pending["id"], "decision": "accept", "digest": payment["digest"]}))

        run_until_waiting(m)
        self.assertEqual(m.phase, "closed")
        exposure = m.view()["exposure"]
        # Same report as `ona demo` on main: outputs, firms, payments, model calls.
        self.assertEqual(exposure["outputs"], {"search": 1, "fetch": 2, "contact": 1})
        self.assertEqual(exposure["payments"], [{"to": "cabinet-b.testnet", "amount": "1000000000000000000000000"}])
        self.assertEqual(exposure["model_calls"], 3)
        self.assertEqual(exposure["firms_contacted"], ["cabinet-b"])
        self.assertEqual(exposure["mode"], "mock")
        self.assertTrue(all(s["status"] == "done" for s in m.steps()))

    def test_wrong_digest_is_refused(self):
        m = mc.Mission(1)
        m.confirm({"id": m.pending["id"], "decision": "accept"})
        run_until_waiting(m)
        m.confirm({"id": m.pending["id"], "decision": "accept", "firm": "cabinet-a"})
        run_until_waiting(m)
        error = m.confirm({"id": m.pending["id"], "decision": "accept", "digest": "00" * 32})
        self.assertEqual(error, "digest does not match the payment screen")
        self.assertEqual(m.phase, "waiting")

    def test_stale_and_unknown(self):
        m = mc.Mission(1)
        self.assertEqual(m.confirm({"id": "c-99", "decision": "accept"}), "stale confirmation")
        self.assertEqual(m.confirm({"id": m.pending["id"], "decision": "maybe"}), "decision must be accept or reject")
        m.confirm({"id": m.pending["id"], "decision": "accept"})
        run_until_waiting(m)
        self.assertEqual(m.confirm({"id": m.pending["id"], "decision": "accept", "firm": "x"}), "unknown firm")

    def test_reject_cancels(self):
        m = mc.Mission(1)
        self.assertIsNone(m.confirm({"id": m.pending["id"], "decision": "reject"}))
        self.assertEqual(m.phase, "cancelled")
        self.assertIsNone(m.pending)
        m.tick()
        self.assertEqual(m.phase, "cancelled")


if __name__ == "__main__":
    unittest.main()
