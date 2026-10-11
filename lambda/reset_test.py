import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hide_my_email as app
import reset
from hide_my_email_test import DOMAIN, OWNER, Base, FakeS3, FakeTable

SEED = Path(__file__).resolve().parent.parent / "seed" / "seed.json"


class ScanTable(FakeTable):
    # The reset scans the whole table, two items a page to exercise paging.
    def scan(self, ProjectionExpression=None, ExclusiveStartKey=None):
        keys = sorted(self.items)
        if ExclusiveStartKey:
            keys = [key for key in keys if key > (ExclusiveStartKey["pk"], ExclusiveStartKey["sk"])]
        page = [{"pk": pk, "sk": sk} for pk, sk in keys[:2]]
        return {"Items": page, **({"LastEvaluatedKey": page[-1]} if len(keys) > 2 else {})}


class ListS3(FakeS3):
    def put_object(self, Bucket, Key, Body, **kwargs):
        super().put_object(Bucket, Key, Body if isinstance(Body, bytes) else Body.encode(), **kwargs)

    # Two objects a page, as list_objects_v2 pages by 1000.
    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        keys = sorted(key for bucket, key in self.objects if bucket == Bucket and key.startswith(Prefix))
        start = int(ContinuationToken or 0)
        page = keys[start:start + 2]
        more = start + 2 < len(keys)
        return {"Contents": [{"Key": key} for key in page], "IsTruncated": more, **({"NextContinuationToken": str(start + 2)} if more else {})}


class FakeCognito:
    def __init__(self, users):
        self.users = {name: dict(attributes) for name, attributes in users.items()}
        self.calls = []

    def list_users(self, UserPoolId, PaginationToken=None):
        names = sorted(self.users)
        start = int(PaginationToken or 0)
        page = names[start:start + 1]
        result = {"Users": [{"Username": name, "Attributes": [{"Name": key, "Value": value} for key, value in self.users[name].items()]} for name in page]}
        if start + 1 < len(names):
            result["PaginationToken"] = str(start + 1)
        return result

    def admin_delete_user(self, UserPoolId, Username):
        self.calls.append(("delete", Username))
        self.users.pop(Username)

    def admin_create_user(self, UserPoolId, Username, MessageAction, UserAttributes):
        self.calls.append(("create", Username, MessageAction))
        self.users[Username] = {attribute["Name"]: attribute["Value"] for attribute in UserAttributes}

    def admin_set_user_password(self, UserPoolId, Username, Password, Permanent):
        self.calls.append(("password", Username, Password, Permanent))

    def admin_set_user_mfa_preference(self, UserPoolId, Username, SoftwareTokenMfaSettings):
        self.calls.append(("mfa", Username, SoftwareTokenMfaSettings["Enabled"]))

    def admin_delete_user_attributes(self, UserPoolId, Username, UserAttributeNames):
        self.calls.append(("attributes", Username, tuple(UserAttributeNames)))
        for name in UserAttributeNames:
            self.users[Username].pop(name, None)

    def admin_user_global_sign_out(self, UserPoolId, Username):
        self.calls.append(("sign out", Username))


class FakeSsm:
    def get_parameter(self, Name, WithDecryption):
        return {"Parameter": {"Value": "Demo-Password-1"}}


class ResetTest(Base):
    def setUp(self):
        super().setUp()
        self.table = app._table = ScanTable()
        self.s3 = app._s3 = ListS3()
        os.environ.update(USER_POOL_ID="pool", DEMO_EMAIL="demo@example.com", DEMO_PASSWORD_PARAMETER="/demo/password")
        self.cognito = reset._cognito = FakeCognito({
            "demo-sub": {"email": "demo@example.com", "locale": "fr"},
            "visitor-sub": {"email": "visitor@example.net"},
        })
        reset._ssm = FakeSsm()
        reset.SEED = SEED
        self.seed = json.loads(SEED.read_text())

    def tearDown(self):
        reset._cognito = reset._ssm = None
        super().tearDown()

    def test_everything_made_since_goes_and_the_examples_come_back(self):
        self.alias("visitor-made-1")
        self.table.items[("TOKEN", "x")] = {"pk": "TOKEN", "sk": "x"}
        for key in ("messages/old", "attachments/old/0", "attachments/old/1"):
            self.s3.objects[("mail", key)] = b"x"
        result = reset.handler({}, None)
        self.assertEqual(result["objects"], 3)
        self.assertNotIn(("ALIAS", "visitor-made-1"), self.table.items)
        self.assertNotIn(("TOKEN", "x"), self.table.items)
        aliases = {key[1] for key in self.table.items if key[0] == "ALIAS"}
        self.assertEqual(aliases, {entry["local"] for entry in self.seed["aliases"]})
        self.assertFalse(self.table.items[("ALIAS", "swift-otter-28")]["active"])
        self.assertTrue(self.table.items[("ALIAS", "travel")]["pinned"])

    def test_the_example_messages_are_logged_like_real_ones(self):
        reset.handler({}, None)
        logged = sorted((item for key, item in self.table.items.items() if key[0] == "MSG"), key=lambda item: item["sk"])
        self.assertEqual(len(logged), len(self.seed["messages"]))
        self.assertEqual([item["subject"] for item in logged][-1], "Your monthly statement", "newest last by id")
        order = self.table.items[("ALIAS", "quiet-river-42")]
        self.assertEqual(order["forwarded"], 2, "incoming ones are counted, the reply is not")
        reply = next(item for item in logged if item["direction"] == "out")
        self.assertEqual((reply["from_address"], reply["to_address"]), (f"quiet-river-42@{DOMAIN}", "orders@shop.example"))
        statement = next(item for item in logged if item["subject"] == "Your monthly statement")
        self.assertEqual(statement["attachments"], 1)
        self.assertEqual(self.s3.objects[("mail", f"attachments/{statement['sk']}/0")], self.seed["messages"][4]["attachments"][0]["content"].encode())
        self.assertEqual(statement["delivered_to"], "work@example.org", "the alias's own forwarding address")
        self.assertTrue(next(item for item in logged if item["subject"] == "You have won!!!")["spam"])

    def test_the_seed_reads_through_the_api(self):
        reset.handler({}, None)
        listed = self.call("GET", "/api/messages")[1]["items"]
        shipped = next(item for item in listed if item["subject"] == "Order #1024 has shipped")
        read = self.call("GET", f"/api/messages/{shipped['id']}")[1]
        self.assertIn("EX123456789", read["text"])
        self.assertNotIn("pixel.gif", read["text"], "HTML comes as text, without the tracker")
        relay = shipped["relay"]
        self.assertTrue(relay.startswith("orders_at_shop_example_"))
        self.assertEqual(self.call("GET", f"/api/relays/{relay}")[1]["alias"], "quiet-river-42")

    def call(self, method, path, body=None):
        event = {
            "rawPath": path,
            "requestContext": {"http": {"method": method}, "authorizer": {"jwt": {"claims": {"email": OWNER, "email_verified": "true"}}}},
            "body": json.dumps(body) if body is not None else None,
        }
        result = app.handler(event, None)
        return result["statusCode"], json.loads(result["body"])

    def test_the_demo_user_is_put_back_and_others_go(self):
        reset.handler({}, None)
        self.assertEqual(set(self.cognito.users), {"demo-sub"})
        self.assertIn(("delete", "visitor-sub"), self.cognito.calls)
        self.assertIn(("password", "demo-sub", "Demo-Password-1", True), self.cognito.calls)
        self.assertIn(("mfa", "demo-sub", False), self.cognito.calls)
        self.assertNotIn("locale", self.cognito.users["demo-sub"], "the default language again")
        self.assertEqual(self.cognito.calls[-1], ("sign out", "demo-sub"))

    def test_a_missing_demo_user_is_made_without_an_email(self):
        self.cognito.users = {}
        reset.handler({}, None)
        self.assertIn(("create", "demo@example.com", "SUPPRESS"), self.cognito.calls)
        self.assertEqual(self.cognito.users["demo@example.com"]["email_verified"], "true")


if __name__ == "__main__":
    unittest.main()
