"""Tests of the mock computer's conversations. Run: python3 -m unittest -v"""

import base64
import unittest

import chats
import mock_computer as mc
import p256
from pairing import PAIR_DOMAIN, Pairing, confirm_message, delete_message, fields, message_message


class Phone:
    """Pairs with a mock computer and signs like the app."""

    def __init__(self, computer: mc.Computer):
        self.computer = computer
        self.d, self.key = p256.generate_keypair()
        pairing = computer.pairing
        proof = p256.sign(self.d, fields(PAIR_DOMAIN, pairing.code, self.key, pairing.computer_key))
        error, self.pairing_id, _ = pairing.pair({"code": pairing.code, "phone_key": b64(self.key),
                                                  "signature": b64(proof)})
        assert error is None, error

    def signed(self, body: dict, message: bytes) -> dict:
        return dict(body, pairing_id=self.pairing_id, signature=b64(p256.sign(self.d, message)))

    def new_chat(self, text: str):
        return self.computer.create_chat(self.signed({"text": text}, message_message(self.pairing_id, None, text)))

    def say(self, chat_id: str, text: str):
        body = self.signed({"text": text}, message_message(self.pairing_id, chat_id, text))
        return self.computer.post_message(chat_id, body)

    def delete(self, chat_id: str):
        return self.computer.delete_chat(chat_id, self.signed({}, delete_message(self.pairing_id, chat_id)))

    def confirm(self, body: dict):
        return self.computer.confirm(self.signed(body, confirm_message(self.pairing_id, body)))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def make_computer() -> mc.Computer:
    computer = mc.Computer.__new__(mc.Computer)  # no background thread: the test ticks by hand
    computer.pairing = Pairing("Test", "http://127.0.0.1:8790")
    computer.lock = mc.threading.Lock()
    computer.mission = None
    computer.missions_started = 0
    computer.chats = {}
    computer.chats_started = 0
    return computer


def tick_until(computer: mc.Computer, chat_id: str, status: str, limit: int = 40) -> dict:
    for _ in range(limit):
        view = computer.chat_view(chat_id)["chat"]
        if view["status"] == status:
            return view
        for chat in computer.chats.values():
            chat.tick()
    raise AssertionError(f"chat never reached {status}")


def pending_confirmation(view: dict) -> dict:
    return next(i for i in view["items"] if i["kind"] == "confirmation" and i["state"] == "pending")["pending"]


class ChatTests(unittest.TestCase):
    def setUp(self):
        self.computer = make_computer()
        self.phone = Phone(self.computer)

    def test_a_request_becomes_a_conversation(self):
        error, chat_id = self.phone.new_chat("Trouve-moi un avocat en droit du travail à Paris")
        self.assertIsNone(error)
        view = self.computer.chat_view(chat_id)["chat"]
        self.assertEqual([i["kind"] for i in view["items"]], ["user", "activity", "agent", "confirmation"])
        self.assertEqual(view["status"], "waiting")
        self.assertEqual(self.computer.chat_list()["chats"][0]["title"],
                         "Trouve-moi un avocat en droit du travail à Paris")

        plan = pending_confirmation(view)
        self.assertEqual(plan["kind"], "plan")
        self.assertIsNone(self.phone.confirm({"id": plan["id"], "decision": "accept"}))
        view = self.computer.chat_view(chat_id)["chat"]
        self.assertEqual(view["status"], "working")
        self.assertEqual(view["working"]["tool"], "search")

        view = tick_until(self.computer, chat_id, "waiting")
        offers = pending_confirmation(view)
        self.assertEqual(offers["kind"], "recipient")
        tools = [i["tool"] for i in view["items"] if i["kind"] == "activity"]
        self.assertEqual(tools, ["think", "search", "read", "read", "compare"])
        self.assertIsNone(self.phone.confirm({"id": offers["id"], "decision": "accept", "firm": "cabinet-b"}))

        view = tick_until(self.computer, chat_id, "waiting")
        payment = pending_confirmation(view)
        self.assertEqual(payment["kind"], "payment")
        self.assertIsNone(self.phone.confirm({"id": payment["id"], "decision": "accept",
                                              "digest": payment["payment"]["digest"]}))

        view = tick_until(self.computer, chat_id, "idle")
        kinds = [i["kind"] for i in view["items"]]
        self.assertEqual(kinds[-2:], ["agent", "exposure"])
        self.assertEqual(view["items"][-1]["exposure"]["firms_contacted"], ["cabinet-b"])
        states = [i["state"] for i in view["items"] if i["kind"] == "confirmation"]
        self.assertEqual(states, ["accepted", "accepted", "accepted"])

    def test_refusing_stops_the_mission(self):
        _, chat_id = self.phone.new_chat("Trouve un avocat")
        plan = pending_confirmation(self.computer.chat_view(chat_id)["chat"])
        self.assertIsNone(self.phone.confirm({"id": plan["id"], "decision": "reject"}))
        view = self.computer.chat_view(chat_id)["chat"]
        self.assertEqual(view["status"], "idle")
        self.assertEqual(view["items"][-2]["text"], chats.CANCELLED_MESSAGE)
        self.assertEqual([i["state"] for i in view["items"] if i["kind"] == "confirmation"], ["rejected"])

    def test_messages_must_be_signed_by_the_paired_phone(self):
        error, _ = self.computer.create_chat({"text": "bonjour", "pairing_id": self.phone.pairing_id})
        self.assertEqual(error, "missing or malformed signature")
        # A signature over another text does not count.
        body = self.phone.signed({"text": "autre chose"}, message_message(self.phone.pairing_id, None, "bonjour"))
        self.assertEqual(self.computer.create_chat(body)[0], "signature does not verify")
        self.assertEqual(self.computer.create_chat(self.phone.signed({"text": "  "}, b""))[0],
                         "empty or too long message")
        self.assertEqual(self.computer.chat_list()["chats"], [])

    def test_two_chats_wait_independently(self):
        _, first = self.phone.new_chat("Premier")
        _, second = self.phone.new_chat("Second")
        plan_a = pending_confirmation(self.computer.chat_view(first)["chat"])
        plan_b = pending_confirmation(self.computer.chat_view(second)["chat"])
        self.assertNotEqual(plan_a["id"], plan_b["id"])
        self.assertIsNone(self.phone.confirm({"id": plan_b["id"], "decision": "accept"}))
        self.assertEqual(self.computer.chat_view(first)["chat"]["status"], "waiting")
        self.assertEqual(self.computer.chat_view(second)["chat"]["status"], "working")

    def test_message_during_a_mission_gets_a_holding_reply(self):
        _, chat_id = self.phone.new_chat("Trouve un avocat")
        self.assertIsNone(self.phone.say(chat_id, "Plutôt à Lyon ?"))
        items = self.computer.chat_view(chat_id)["chat"]["items"]
        self.assertEqual(items[-2]["text"], "Plutôt à Lyon ?")
        self.assertEqual(items[-1]["text"], chats.BUSY_MESSAGE)

    def test_delete(self):
        _, chat_id = self.phone.new_chat("À supprimer")
        self.assertEqual(self.computer.delete_chat(chat_id, {"pairing_id": self.phone.pairing_id}),
                         "missing or malformed signature")
        self.assertIsNone(self.phone.delete(chat_id))
        self.assertIsNone(self.computer.chat_view(chat_id))
        self.assertEqual(self.phone.delete(chat_id), "unknown chat")

    def test_long_titles_are_cut(self):
        self.assertEqual(chats.title_from("a " * 40)[-1], "…")
        self.assertEqual(chats.title_from("  deux   mots "), "deux mots")


if __name__ == "__main__":
    unittest.main()
