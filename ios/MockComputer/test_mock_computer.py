"""Tests of the fake computer over HTTP, protocol v1. Run: python3 -m unittest -v (from this folder)."""

import base64
import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

import mock_computer as mc
import p256
import pairing as proto
from chats import title_from
from test_pairing import Phone


class Client:
    """The phone over HTTP: a nonce per request, every reply checked with the computer's key before it is read."""

    def __init__(self, port: int, computer_key: bytes):
        self.port = port
        self.computer_key = computer_key

    def post(self, path: str, body: dict) -> tuple[int, dict]:
        nonce = proto.random_hex16()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        data = json.dumps({**body, "nonce": nonce})
        connection.request("POST", path, body=data, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        status, envelope = response.status, json.loads(response.read())
        connection.close()
        reply = envelope["reply"]
        message = proto.reply_message(nonce, "POST", path, status, reply.encode("utf-8"))
        assert p256.verify(self.computer_key, message, base64.b64decode(envelope["signature"]), low_s=True), path
        return status, json.loads(reply)


class HTTPFlow(unittest.TestCase):
    def setUp(self):
        self.pairing = proto.Pairing("Ordinateur simulé", "http://127.0.0.1:0")
        self.computer = mc.Computer(step_seconds=3600, pairing=self.pairing)  # steps run by hand
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), mc.make_handler(self.computer))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client = Client(self.server.server_address[1], self.pairing.computer_key)
        self.phone = Phone()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def pair_over_http(self):
        phone, code = self.phone, self.pairing.code
        status, committed = self.client.post("/v1/pair", {"code": code,
                                                          "commitment": proto.commitment(phone.key, phone.nonce)})
        self.assertEqual(status, 200)
        message = proto.pair_message(committed["pairing_id"], code, phone.key, self.pairing.computer_key, phone.nonce,
                                     committed["computer_nonce"])
        status, revealed = self.client.post("/v1/pair/reveal", {
            "pairing_id": committed["pairing_id"], "phone_key": base64.b64encode(phone.key).decode(),
            "phone_nonce": phone.nonce, "signature": phone.sign(message)})
        self.assertEqual(status, 200)
        phone.pairing_id, phone.token = revealed["pairing_id"], revealed["token"]

    def view(self, chat_id: str) -> dict:
        status, reply = self.client.post(f"/v1/chats/{chat_id}/view", {"token": self.phone.token})
        self.assertEqual(status, 200)
        return reply["chat"]

    def pending(self, chat_id: str) -> dict:
        items = [i for i in self.view(chat_id)["items"] if i["kind"] == "confirmation" and i["state"] == "pending"]
        self.assertEqual(len(items), 1)
        return items[0]["pending"]

    def run_until_waiting(self, chat_id: str) -> None:
        for _ in range(30):
            with self.computer.lock:
                chat = self.computer.chats[chat_id]
                if chat.status != "working":
                    return
                chat.tick()
        raise AssertionError("mission never stopped")

    def confirm(self, pending: dict, decision: str = "accept", firm=None, digest=None, content=None) -> tuple[int, dict]:
        if content is None:
            if pending["kind"] == "plan":
                content = proto.plan_digest(pending["id"], pending["plan"])
            elif pending["kind"] == "recipient":
                content = proto.offers_digest(pending["id"], pending["offers"])
            else:
                p = pending["payment"]
                content = proto.payment_digest(p["network"], p["contract"], p["mission_id"], p["nonce"], p["to"],
                                               p["amount"])
        body = {"id": pending["id"], "decision": decision}
        if firm:
            body["firm"] = firm
        if digest:
            body["digest"] = digest
        signed = lambda pid, c: proto.confirm_message(pid, c, body, content)  # noqa: E731
        return self.client.post("/v1/confirm", self.phone.write(signed, **body))

    def new_chat(self, text: str) -> str:
        body = self.phone.write(lambda pid, c: proto.chat_message(pid, c, None, text), text=text)
        status, reply = self.client.post("/v1/chats", body)
        self.assertEqual(status, 200, reply)
        return reply["chat_id"]

    def test_full_mission(self):
        self.assertEqual(self.client.post("/v1/chats/list", {"token": "x"}), (403, {"ok": False, "error": "not paired",
                                                                                    "mode": "mock"}))
        self.pair_over_http()
        chat_id = self.new_chat("Trouve-moi un avocat")
        self.assertTrue(chat_id.startswith("chat-") and len(chat_id) == 37)

        plan = self.pending(chat_id)
        self.assertEqual(plan["kind"], "plan")
        self.assertEqual(plan["content"], proto.plan_digest(plan["id"], plan["plan"]))
        self.assertEqual(self.confirm(plan)[0], 200)
        # Replaying the same confirmation (new counter): refused.
        self.assertEqual(self.confirm(plan)[1]["error"], "replayed request")

        self.run_until_waiting(chat_id)
        recipient = self.pending(chat_id)
        self.assertEqual(self.confirm(recipient, firm="cabinet-b")[0], 200)

        self.run_until_waiting(chat_id)
        payment = self.pending(chat_id)
        p = payment["payment"]
        self.assertEqual(p["digest_version"], 2)
        self.assertEqual(p["digest"], proto.payment_digest(p["network"], p["contract"], p["mission_id"], p["nonce"],
                                                           p["to"], p["amount"]))
        self.assertEqual(p["screen"], f"Pay {p['amount']} yoctoNEAR to {p['to']}")
        # A wrong digest is refused by the agent; the phone may answer again with a new counter.
        self.assertEqual(self.confirm(payment, digest="00" * 32)[1]["error"], "payment digest does not match")
        self.assertEqual(self.confirm(payment, digest=p["digest"])[0], 200)

        self.run_until_waiting(chat_id)
        chat = self.view(chat_id)
        self.assertEqual(chat["status"], "idle")
        exposure = chat["items"][-1]["exposure"]
        self.assertEqual(exposure["firms_contacted"], ["cabinet-b"])
        self.assertEqual(exposure["payments"], [{"to": "cabinet-b.testnet", "amount": p["amount"]}])
        self.assertEqual(exposure["mode"], "mock")

    def test_a_confirmation_over_something_else_is_refused(self):
        self.pair_over_http()
        chat_id = self.new_chat("Trouve-moi un avocat")
        plan = self.pending(chat_id)
        status, reply = self.confirm(plan, content=proto.plan_digest(plan["id"], ["search"]))
        self.assertEqual((status, reply["error"]), (409, "signature does not verify"))

    def test_reject_stops_the_mission(self):
        self.pair_over_http()
        chat_id = self.new_chat("Trouve-moi un avocat")
        self.assertEqual(self.confirm(self.pending(chat_id), decision="reject")[0], 200)
        chat = self.view(chat_id)
        self.assertEqual(chat["items"][-1]["kind"], "exposure")
        self.assertIn("rejected", [i.get("state") for i in chat["items"]])

    def test_writes_need_the_token_and_a_valid_counter(self):
        self.pair_over_http()
        body = self.phone.write(lambda pid, c: proto.chat_message(pid, c, None, "a"), text="a")
        self.assertEqual(self.client.post("/v1/chats", dict(body, token="x"))[1]["error"], "missing or wrong token")
        self.assertEqual(self.client.post("/v1/chats", dict(body, counter=1.5))[1]["error"], "replayed request")
        self.assertEqual(self.client.post("/v1/chats", dict(body, counter=True))[1]["error"], "replayed request")
        self.assertEqual(self.client.post("/v1/chats", body)[0], 200)

    def test_two_chats_wait_independently_and_delete(self):
        self.pair_over_http()
        first, second = self.new_chat("Premier"), self.new_chat("Second")
        self.assertNotEqual(self.pending(first)["id"], self.pending(second)["id"])
        body = self.phone.write(lambda pid, c: proto.delete_message(pid, c, first))
        self.assertEqual(self.client.post(f"/v1/chats/{first}/delete", body)[0], 200)
        status, reply = self.client.post("/v1/chats/list", {"token": self.phone.token})
        self.assertEqual([c["id"] for c in reply["chats"]], [second])

    def test_message_during_a_mission_gets_a_holding_reply(self):
        self.pair_over_http()
        chat_id = self.new_chat("Trouve-moi un avocat")
        body = self.phone.write(lambda pid, c: proto.chat_message(pid, c, chat_id, "Et vite"), text="Et vite")
        self.assertEqual(self.client.post(f"/v1/chats/{chat_id}/messages", body)[0], 200)
        self.assertTrue(self.view(chat_id)["items"][-1]["text"].startswith("Je suis encore sur la mission"))

    def test_get_and_v0_are_not_served(self):
        status, reply = self.client.post("/v0/chats", {})
        self.assertEqual(status, 404)
        connection = http.client.HTTPConnection("127.0.0.1", self.client.port, timeout=5)
        connection.request("GET", "/v1/chats/list")
        self.assertEqual(connection.getresponse().status, 404)

    def test_the_pool_portfolio_is_a_signed_read(self):
        self.assertEqual(self.client.post("/v1/pool/portfolio", {"token": "x"})[0], 403)
        self.pair_over_http()
        status, reply = self.client.post("/v1/pool/portfolio", {"token": self.phone.token})
        self.assertEqual(status, 200)
        self.assertEqual(reply["mode"], "mock")
        portfolio = reply["portfolio"]
        values = [int(portfolio["cash"]["value"])] + [int(v["value"]) for v in portfolio["vaults"]]
        self.assertEqual(int(portfolio["total"]), sum(values))

    def test_long_titles_are_cut(self):
        self.assertEqual(len(title_from("x" * 100)), 48)


if __name__ == "__main__":
    unittest.main()
