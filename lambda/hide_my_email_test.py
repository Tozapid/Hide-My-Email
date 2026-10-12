import base64
import email
import email.header
import hashlib
import email.policy
import email.utils
import io
import json
import re
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import hide_my_email as app

OWNER = "me@example.org"
# A throwaway 1024-bit key for signing tests only; the real one is made by
# Terraform and lives in SSM.
TEST_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC9ehXYbZiFOPJik3WL96QDf2jLCi+5KH+AZRiwGqLiJYRoFnwM
CeyNoMBYgyUcedjfbrCj5NAjV7e3Bl3lX5j/GY/xdf92lJpSQkc+hvWuzs4lV4jQ
ZuzTGjEwOynyEXFGp58rqX5iRHdLBRo5GCXheJULXei2JKASofHzifyKuwIDAQAB
AoGAUcL02kewoQxJy6/F8XgTFk9McREcNtH68vStCpDz6JI36JKLRMajhRnw5kDx
KrCJnSCuqIp8JkQbyqa8rdXqtqu9G57P7xrkh/Vwpy9BIqJd3acZ9/qi/fbHunPU
GTTeJn9lizzTjJXO1ZUNRhp6ODmG1oVmuTUHNo80HiAlc8ECQQDgaYHnYqSDC9mT
3gHYOAi5zaEzT+d7QBEenQ0UEk5dRxsJM81QHO5XqyBw+VPTve7540MhvGABrXmV
OUSUdzqtAkEA2CW3po0NWpgTyMQUosnxXaIni6O8V2gr/NSmtIoD8H7MHu0L6k0p
rv5SX6vpLhkhmwTGBix+cJOf3xLL40+wBwJAOuET10zXUxbJ2HUYUM2q5G0iTV86
oejWVQzpwIlpDCo62rg/tzRQCKp6kYmpR9X+nIvXMkPFgMsuKkvjRXze5QJAfVIx
DwINUg+GuQrnJBOOPEm+P/ppQwyFJIxvM5IqApCh7PRnyit/FZUjUZEtG6s6jtTP
s9isXr1ZHk+Zo2walQJACxvAc8dalmFpqdOhrUH6cqJiOaO6PTZypt+bFZMF5qDO
HLx4QARljlsS5Ajm464dAxafOZ4xQE3Q6XjRyY++3g==
-----END RSA PRIVATE KEY-----
"""
DOMAIN = "hide.example.com"
# The second alias domain, with DNS outside Route 53.
OTHER = "hide.example.net"


# The fields the addy.io iOS app declares without "?" (addy_shared/models in
# anonaddy/addy-ios): its decoder fails on a missing or null one.
IOS_REQUIRED = {
    "account": {"id": str, "username": str, "banner_location": str, "bandwidth": int, "username_count": int, "username_limit": int,
                "default_username_id": str, "default_recipient_id": str, "default_alias_domain": str, "default_alias_format": str,
                "recipient_count": int, "active_domain_count": int, "active_shared_domain_alias_count": int, "active_rule_count": int,
                "total_emails_forwarded": int, "total_emails_blocked": int, "total_emails_replied": int, "total_emails_sent": int,
                "total_aliases": int, "total_active_aliases": int, "total_inactive_aliases": int, "total_pinned_aliases": int,
                "total_deleted_aliases": int, "created_at": str, "updated_at": str},
    "alias": {"id": str, "user_id": str, "local_part": str, "domain": str, "email": str, "active": bool, "pinned": bool,
              "attached_recipients_only": bool, "emails_forwarded": int, "emails_blocked": int, "emails_replied": int, "emails_sent": int,
              "created_at": str, "updated_at": str},
    "recipient": {"id": str, "user_id": str, "email": str, "can_reply_send": bool, "should_encrypt": bool, "inline_encryption": bool,
                  "protected_headers": bool, "remove_pgp_keys": bool, "remove_pgp_signatures": bool, "active": bool, "created_at": str, "updated_at": str},
    "meta": {"current_page": int, "last_page": int, "links": list, "path": str, "per_page": int, "total": int},
    "token": {"created_at": str, "name": str},
    "version": {"major": int, "minor": int, "patch": int},
}
ADDY_TIME = re.compile(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")


class ConditionFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


# A few of DynamoDB's reserved words, those that come near the fields here.
RESERVED_WORDS = {"COMMENT", "NAME", "SIZE", "STATUS", "DATA", "DOMAIN", "KEY", "VALUE", "DATE", "TIME", "TIMESTAMP", "USER", "TOKEN", "ACTION"}


class ReservedWord(Exception):
    response = {"Error": {"Code": "ValidationException"}}


class FakeTable:
    def __init__(self):
        self.items = {}

    def get_item(self, Key):
        item = self.items.get((Key["pk"], Key["sk"]))
        return {"Item": dict(item)} if item else {}

    def put_item(self, Item, ConditionExpression=None):
        key = (Item["pk"], Item["sk"])
        if ConditionExpression and key in self.items:
            raise ConditionFailed()
        self.items[key] = dict(Item)

    # Understands the expressions the function writes: "SET a = :a, ..." with
    # an optional counter and "REMOVE b", names as #a. Like DynamoDB, it
    # refuses a reserved word as a bare name.
    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ConditionExpression=None, ReturnValues=None, ExpressionAttributeNames=None):
        key = (Key["pk"], Key["sk"])
        names = ExpressionAttributeNames or {}

        def field_name(token):
            if token.startswith("#"):
                return names[token]
            if token.upper() in RESERVED_WORDS:
                raise ReservedWord(token)
            return token

        if ConditionExpression and key not in self.items:
            raise ConditionFailed()
        item = self.items.setdefault(key, {"pk": Key["pk"], "sk": Key["sk"]})
        sets, _, removes = UpdateExpression.partition(" REMOVE ")
        for assignment in re.split(r", (?![^()]*\))", sets.removeprefix("SET ")):
            field, _, value = assignment.partition(" = ")
            field = field_name(field)
            if value.startswith("if_not_exists"):
                item[field] = item.get(field, 0) + ExpressionAttributeValues[":one"]
            else:
                item[field] = ExpressionAttributeValues[value]
        for field in filter(None, removes.split(", ")):
            item.pop(field_name(field), None)
        return {"Attributes": dict(item)}

    def delete_item(self, Key, ConditionExpression=None):
        key = (Key["pk"], Key["sk"])
        if ConditionExpression and key not in self.items:
            raise ConditionFailed()
        self.items.pop(key, None)

    # One partition sorted by sk, two items a page, to exercise paging.
    def query(self, KeyConditionExpression, ScanIndexForward=True, ExclusiveStartKey=None):
        pk = KeyConditionExpression.get_expression()["values"][1]
        items = sorted((item for (key, _), item in self.items.items() if key == pk), key=lambda item: item["sk"], reverse=not ScanIndexForward)
        if ExclusiveStartKey:
            after = ExclusiveStartKey["sk"]
            items = [item for item in items if (item["sk"] < after if not ScanIndexForward else item["sk"] > after)]
        page = [dict(item) for item in items[:2]]
        return {"Items": page, **({"LastEvaluatedKey": {"pk": pk, "sk": page[-1]["sk"]}} if len(items) > 2 else {})}

    def batch_writer(self):
        table = self

        class Batch:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def delete_item(self, Key):
                table.items.pop((Key["pk"], Key["sk"]), None)

        return Batch()


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.put = {}

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise NoSuchKey()
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def put_object(self, Bucket, Key, Body, **kwargs):
        self.objects[(Bucket, Key)] = Body
        self.put[Key] = {"Body": Body, **kwargs}

    def copy_object(self, Bucket, Key, CopySource):
        self.objects[(Bucket, Key)] = self.objects[(CopySource["Bucket"], CopySource["Key"])]

    def delete_objects(self, Bucket, Delete):
        for entry in Delete["Objects"]:
            self.objects.pop((Bucket, entry["Key"]), None)


class NoSuchKey(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class FakeSsm:
    def __init__(self):
        self.reads = 0

    def get_parameter(self, Name, WithDecryption):
        self.reads += 1
        return {"Parameter": {"Value": TEST_KEY}}


class NotFound(Exception):
    response = {"Error": {"Code": "NotFoundException"}}


class FakeSes:
    def __init__(self):
        self.sent = []
        self.sources = []
        self.identities = {}
        self.production = False
        self.verify_requests = []

    def get_email_identity(self, EmailIdentity):
        if EmailIdentity not in self.identities:
            raise NotFound()
        return {"VerifiedForSendingStatus": self.identities[EmailIdentity]}

    def get_account(self):
        return {"ProductionAccessEnabled": self.production}

    def verify_email_identity(self, EmailAddress):
        self.verify_requests.append(EmailAddress)
        self.identities.setdefault(EmailAddress, False)

    def send_email(self, FromEmailAddress, Destination, Content):
        self.raw = getattr(self, "raw", []) + [Content["Raw"]["Data"]]
        message = email.message_from_bytes(Content["Raw"]["Data"], policy=email.policy.default)
        self.sources.append(FromEmailAddress)
        self.sent.append((email.utils.parseaddr(FromEmailAddress)[1], Destination["ToAddresses"], message))


def raw_message(sender, to, subject="Hello", body="Hi there", headers=None):
    message = email.message.EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = subject
    for name, value in (headers or {}).items():
        message[name] = value
    message.set_content(body)
    return message.as_bytes()


def passed(**overrides):
    receipt = {name: {"status": "PASS"} for name in ("spfVerdict", "dkimVerdict", "dmarcVerdict", "spamVerdict", "virusVerdict")}
    receipt.update({name: {"status": value} for name, value in overrides.items()})
    return receipt


class Base(unittest.TestCase):
    def setUp(self):
        os.environ.update(DOMAIN=DOMAIN, DOMAINS=f"{DOMAIN},{OTHER}", FORWARD_TO=OWNER, MAIL_BUCKET="mail", MAIL_PREFIX="incoming/", MESSAGES_PREFIX="messages/", ATTACHMENTS_PREFIX="attachments/", TABLE_NAME="relay",
                          SIGNING_KEY_PARAMETER="/hide-my-email/key", CLOUDFRONT_KEY_PAIR_ID="K123", PGP_SECRET_PARAMETER="/hide-my-email/pgp-secret")
        self.table = app._table = FakeTable()
        self.s3 = app._s3 = FakeS3()
        self.ses = app._ses = app._ses_v1 = FakeSes()
        self.ssm = app._ssm = FakeSsm()
        app._signing_key = app._pgp_secret = None
        self.count = 0

    def tearDown(self):
        app._table = app._s3 = app._ses = app._ses_v1 = app._ssm = app._signing_key = app._pgp_secret = None

    def deliver(self, raw, recipients, source, receipt=None):
        self.count += 1
        message_id = f"m{self.count}"
        self.s3.objects[("mail", "incoming/" + message_id)] = raw
        event = {"Records": [{"ses": {
            "mail": {"messageId": message_id, "source": source},
            "receipt": dict(receipt or passed(), recipients=recipients),
        }}]}
        app.handler(event, None)

    def alias(self, local="quiet-river-42", active=True, forward=None, sender_name=None, domain=None):
        self.table.items[("ALIAS", local)] = {"pk": "ALIAS", "sk": local, "comment": "shop", "active": active}
        if domain:
            self.table.items[("ALIAS", local)]["domain"] = domain
        if forward:
            self.table.items[("ALIAS", local)]["forward_to"] = forward
        if sender_name:
            self.table.items[("ALIAS", local)]["sender_name"] = sender_name
        return f"{local}@{domain or DOMAIN}"



class RelayTest(Base):
    # Forwarding

    def test_mail_to_an_alias_is_forwarded_from_a_reply_address(self):
        alias = self.alias()
        raw = raw_message("Shop News <news@shop.test>", alias, headers={
            "DKIM-Signature": "v=1; d=shop.test; b=abc",
            "Sender": "bounces@shop.test",
            "Return-Path": "<bounces@shop.test>",
            "Authentication-Results": "amazonses.com; spf=pass smtp.mailfrom=bounces@shop.test; dkim=pass header.i=@shop.test",
            "Received-SPF": "pass (spfCheck: domain of shop.test designates 1.2.3.4 as permitted sender)",
            "ARC-Seal": "i=1; a=rsa-sha256; d=shop.test; b=x",
            "X-SES-RECEIPT": "AEFBQUFB",
            "X-SES-DKIM-SIGNATURE": "a=rsa-sha256; b=y",
            "X-Google-Smtp-Source": "AGHT+",
            "Received": "from mail.shop.test (mail.shop.test [1.2.3.4]) by inbound-smtp",
            "List-Unsubscribe": "<https://shop.test/unsubscribe>",
        })
        self.deliver(raw, [alias], "bounces@shop.test")
        [(source, to, message)] = self.ses.sent
        self.assertEqual(to, [OWNER])
        self.assertRegex(source, rf"^news_at_shop_test_[a-z2-7]{{12}}@{re.escape(DOMAIN)}$", "the sender's address in the relay address")
        self.assertEqual(message["From"].addresses[0].addr_spec, source)
        self.assertEqual(message["From"].addresses[0].display_name, "Shop News", "just the sender's name")
        for name in ("DKIM-Signature", "Sender", "Return-Path", "Authentication-Results", "Received-SPF", "ARC-Seal",
                     "X-SES-RECEIPT", "X-SES-DKIM-SIGNATURE", "X-Google-Smtp-Source"):
            self.assertIsNone(message[name], name)
        self.assertIsNotNone(message["Received"], "the trace of a forwarded message stays")
        self.assertEqual(message["List-Unsubscribe"], "<https://shop.test/unsubscribe>", "other headers stay")
        self.assertEqual(message["X-Hide-My-Email-Alias"], alias)
        code = app.relay_code(source)
        self.assertEqual(self.table.items[("REPLY", code)]["sender"], "news@shop.test")
        self.assertEqual(self.table.items[("REPLY", code)]["alias"], "quiet-river-42")
        self.assertEqual(self.table.items[("ALIAS", "quiet-river-42")]["forwarded"], 1, "counted")
        self.assertTrue(self.table.items[("ALIAS", "quiet-river-42")]["last_at"])

    def test_an_alias_can_forward_somewhere_else_and_only_that_address_replies(self):
        alias = self.alias(forward="work@example.net")
        self.deliver(raw_message("Shop <news@shop.test>", alias), [alias], "news@shop.test")
        relay, to, _ = self.ses.sent[-1]
        self.assertEqual(to, ["work@example.net"])
        self.deliver(raw_message(OWNER, relay), [relay], OWNER)
        self.assertEqual(len(self.ses.sent), 1, "the default address may not reply for this alias")
        self.deliver(raw_message("work@example.net", relay, body="from work@example.net"), [relay], "work@example.net")
        source, to, message = self.ses.sent[-1]
        self.assertEqual((source, to), (alias, ["news@shop.test"]))
        self.assertNotIn("work@example.net", message.get_body(("plain",)).get_content())

    def test_reply_to_wins_over_from(self):
        alias = self.alias()
        raw = raw_message("noreply@shop.test", alias, headers={"Reply-To": "Support <help@shop.test>"})
        self.deliver(raw, [alias], "noreply@shop.test")
        code = app.relay_code(self.ses.sent[0][0])
        self.assertEqual(self.table.items[("REPLY", code)]["sender"], "help@shop.test")
        self.assertIsNone(self.ses.sent[0][2]["Reply-To"])

    def test_the_same_sender_keeps_its_reply_address(self):
        alias = self.alias()
        for _ in range(2):
            self.deliver(raw_message("news@shop.test", alias), [alias], "news@shop.test")
        self.assertEqual(self.ses.sent[0][0], self.ses.sent[1][0])

    def test_unknown_or_switched_off_aliases_and_viruses_are_dropped(self):
        off = self.alias("gentle-moss-11", active=False)
        on = self.alias()
        self.deliver(raw_message("x@spam.test", f"nobody@{DOMAIN}"), [f"nobody@{DOMAIN}"], "x@spam.test")
        self.deliver(raw_message("x@spam.test", off), [off], "x@spam.test")
        self.deliver(raw_message("x@spam.test", on), [on], "x@spam.test", passed(virusVerdict="FAIL"))
        self.assertEqual(self.ses.sent, [])

    def test_spam_is_forwarded_with_a_mark(self):
        alias = self.alias()
        self.deliver(raw_message("x@spam.test", alias, subject="Win"), [alias], "x@spam.test", passed(spamVerdict="FAIL"))
        self.assertEqual(self.ses.sent[0][2]["Subject"], "Win", "the subject stays as it was")
        self.assertEqual(self.ses.sent[0][2]["X-Hide-My-Email-Spam"], "yes")

    def test_every_recipient_is_handled(self):
        first, second = self.alias("bold-fox-10"), self.alias("calm-owl-20")
        self.deliver(raw_message("news@shop.test", f"{first}, {second}"), [first, second], "news@shop.test")
        self.assertEqual(len(self.ses.sent), 2)

    # Replies

    def forwarded_reply_address(self):
        alias = self.alias()
        self.deliver(raw_message("Shop <news@shop.test>", alias), [alias], "news@shop.test")
        return self.ses.sent[-1][0]

    def test_the_owner_replies_from_the_alias(self):
        relay = self.forwarded_reply_address()
        body = f"Thanks!\n\nOn Monday, Me <{OWNER.upper()}> wrote:\n> Hi there"
        raw = raw_message(f"Ivan Petrov <{OWNER}>", relay, subject="Re: Hello", body=body, headers={"Cc": "friend@else.test"})
        self.deliver(raw, [relay], OWNER)
        source, to, message = self.ses.sent[-1]
        self.assertEqual((source, to), (f"quiet-river-42@{DOMAIN}", ["news@shop.test"]))
        self.assertEqual(message["From"].addresses[0].addr_spec, f"quiet-river-42@{DOMAIN}")
        self.assertEqual(message["From"].addresses[0].display_name, "Ivan Petrov", "no name set: the one from the owner's message")
        self.assertEqual(message["To"].addresses[0].addr_spec, "news@shop.test")
        self.assertIsNone(message["Cc"], "only the original sender gets the reply")
        text = message.get_body(("plain",)).get_content()
        self.assertNotIn(OWNER, text.lower())
        self.assertIn(f"quiet-river-42@{DOMAIN}", text)

    def test_ses_gets_the_name_with_the_address(self):
        relay = self.forwarded_reply_address()
        self.assertEqual(str(email.header.make_header(email.header.decode_header(self.ses.sources[-1]))), f"Shop <{relay}>")
        self.deliver(raw_message(f"Ivan Petrov <{OWNER}>", relay), [relay], OWNER)
        self.assertEqual(self.ses.sources[-1], f"Ivan Petrov <quiet-river-42@{DOMAIN}>", "a bare address would drop the name")

    def test_without_a_name_the_address_is_shown_without_at(self):
        alias = self.alias()
        for shown in ("news@shop.test", "news@shop.test <news@shop.test>"):
            self.deliver(raw_message(shown, alias), [alias], "news@shop.test")
            self.assertEqual(self.ses.sent[-1][2]["From"].addresses[0].display_name, "news at shop.test", shown)

    def test_the_aliases_own_sender_name_wins(self):
        relay = self.forwarded_reply_address()
        self.table.items[("ALIAS", "quiet-river-42")]["sender_name"] = "Ivan from Berlin"
        self.deliver(raw_message(f"Ivan Petrov <{OWNER}>", relay), [relay], OWNER)
        sent_from = self.ses.sent[-1][2]["From"].addresses[0]
        self.assertEqual((sent_from.display_name, sent_from.addr_spec), ("Ivan from Berlin", f"quiet-river-42@{DOMAIN}"))

    def test_the_name_from_the_owners_message_is_kept_as_is(self):
        relay = self.forwarded_reply_address()
        local = OWNER.split("@")[0]
        self.deliver(raw_message(f"{local.title()} <{OWNER}>", relay), [relay], OWNER)
        self.assertEqual(self.ses.sent[-1][2]["From"].addresses[0].display_name, local.title(), "even the start of the personal address")
        self.deliver(raw_message(OWNER, relay), [relay], OWNER)
        self.assertEqual(str(self.ses.sent[-1][2]["From"]), f"quiet-river-42@{DOMAIN}", "no name at all")

    def test_a_reply_keeps_no_trace_of_the_personal_address(self):
        relay = self.forwarded_reply_address()
        raw = raw_message(f"Me <{OWNER}>", relay, subject="Re: Hello", headers={
            "Authentication-Results": f"amazonses.com; spf=pass smtp.mailfrom={OWNER}; dmarc=pass header.from=example.org",
            "Received-SPF": f"pass (domain of {OWNER} designates 9.9.9.9 as permitted sender)",
            "Received": f"from laptop.home (93.1.2.3) by mail.example.org for <{relay}>",
            "X-Originating-IP": "[93.1.2.3]",
            "ARC-Authentication-Results": f"i=1; mx.example.org; spf=pass smtp.mailfrom={OWNER}",
            "Return-Path": f"<{OWNER}>",
            "Message-ID": "<abc@mail.example.org>",
        })
        self.deliver(raw, [relay], OWNER)
        _, _, message = self.ses.sent[-1]
        headers = "\n".join(f"{name}: {value}" for name, value in message.items()).lower()
        self.assertNotIn(OWNER, headers)
        self.assertNotIn("93.1.2.3", headers)
        self.assertIsNone(message["Received"])

    def test_a_reply_not_from_the_owner_is_dropped(self):
        relay = self.forwarded_reply_address()
        sent = len(self.ses.sent)
        self.deliver(raw_message("evil@else.test", relay), [relay], "evil@else.test")
        self.deliver(raw_message(OWNER, relay), [relay], OWNER, passed(dmarcVerdict="FAIL"))
        self.deliver(raw_message(OWNER, relay), [relay], "bounce@else.test")
        self.deliver(raw_message(OWNER, f"r-unknowncode@{DOMAIN}"), [f"r-unknowncode@{DOMAIN}"], OWNER)
        self.assertEqual(len(self.ses.sent), sent)

    def test_the_older_r_address_still_takes_replies(self):
        relay = self.forwarded_reply_address()
        old = f"r-{app.relay_code(relay)}@{DOMAIN}"
        self.deliver(raw_message(OWNER, old), [old], OWNER)
        self.assertEqual(self.ses.sent[-1][:2], (f"quiet-river-42@{DOMAIN}", ["news@shop.test"]))

    def test_a_long_sender_still_fits_a_local_part(self):
        sender = "very.long.newsletter.sender.name+tag@mail.some-really-long-domain.example"
        relay = app.relay_address(sender, "abcdefghijkl")
        local = relay.split("@")[0]
        self.assertLessEqual(len(local), 64)
        self.assertTrue(local.startswith("very_long_newsletter") and local.endswith("_abcdefghijkl"))
        self.assertEqual(app.relay_code(relay), "abcdefghijkl")
        self.assertEqual(app.relay_address("", "abcdefghijkl"), f"r_abcdefghijkl@{DOMAIN}")

    # The message log

    def test_forwarded_messages_and_replies_are_logged_with_a_copy(self):
        relay = self.forwarded_reply_address()
        self.deliver(raw_message(f"Me <{OWNER}>", relay, subject="Re: Hello"), [relay], OWNER)
        logged = sorted((item for key, item in self.table.items.items() if key[0] == "MSG"), key=lambda item: item["sk"])
        self.assertEqual([item["direction"] for item in logged], ["in", "out"])
        first, second = logged
        self.assertEqual((first["from_name"], first["from_address"], first["to_address"], first["delivered_to"], first["relay"]),
                         ("Shop", "news@shop.test", f"quiet-river-42@{DOMAIN}", OWNER, relay))
        self.assertEqual((second["from_address"], second["to_address"], second["subject"]), (f"quiet-river-42@{DOMAIN}", "news@shop.test", "Re: Hello"))
        self.assertEqual(self.s3.objects[("mail", "messages/" + first["sk"])], self.s3.objects[("mail", "incoming/m1")])

    def test_a_failed_log_does_not_stop_forwarding(self):
        alias = self.alias()
        self.s3.copy_object = None
        with self.assertLogs(app.logger, "ERROR"):
            self.deliver(raw_message("news@shop.test", alias), [alias], "news@shop.test")
        self.assertEqual(len(self.ses.sent), 1)

    def test_spf_counts_when_the_owners_domain_has_no_dmarc(self):
        relay = self.forwarded_reply_address()
        self.deliver(raw_message(OWNER, relay), [relay], OWNER, passed(dmarcVerdict="GRAY"))
        self.assertEqual(self.ses.sent[-1][1], ["news@shop.test"])

    def test_mail_to_the_old_command_addresses_is_dropped(self):
        for name in ("new", "list", "off"):
            self.deliver(raw_message(OWNER, f"{name}@{DOMAIN}", subject="Shop"), [f"{name}@{DOMAIN}"], OWNER)
        self.assertEqual(self.ses.sent, [], "no answers")
        self.assertEqual([key for key in self.table.items if key[0] == "ALIAS"], [], "nothing created")

    # The second domain

    def test_an_alias_of_the_second_domain_forwards_and_replies_there(self):
        alias = self.alias("calm-owl-20", domain=OTHER)
        self.assertEqual(alias, f"calm-owl-20@{OTHER}")
        self.deliver(raw_message("Shop <news@shop.test>", alias), [alias], "news@shop.test")
        relay, to, message = self.ses.sent[-1]
        self.assertTrue(relay.endswith("@" + OTHER), "the relay address is on the alias's domain")
        self.assertEqual(message["X-Hide-My-Email-Alias"], alias)
        self.deliver(raw_message(f"Me <{OWNER}>", relay), [relay], OWNER)
        source, to, reply = self.ses.sent[-1]
        self.assertEqual((source, to), (alias, ["news@shop.test"]))
        logged = sorted((item for key, item in self.table.items.items() if key[0] == "MSG"), key=lambda item: item["sk"])
        self.assertEqual([item["alias_domain"] for item in logged], [OTHER, OTHER])

    def test_a_name_answers_only_on_its_own_domain(self):
        self.alias("calm-owl-20", domain=OTHER)
        self.alias("bold-fox-10")
        self.deliver(raw_message("x@spam.test", f"calm-owl-20@{DOMAIN}"), [f"calm-owl-20@{DOMAIN}"], "x@spam.test")
        self.deliver(raw_message("x@spam.test", f"bold-fox-10@{OTHER}"), [f"bold-fox-10@{OTHER}"], "x@spam.test")
        self.assertEqual(self.ses.sent, [])
        self.deliver(raw_message("x@spam.test", f"bold-fox-10@{DOMAIN}"), [f"bold-fox-10@{DOMAIN}"], "x@spam.test")
        self.assertEqual(len(self.ses.sent), 1, "an alias made before has the first domain")

    def test_mail_for_another_domain_is_ignored(self):
        self.assertEqual(app.route("someone@other.test", b"", {}, {}), "other domain")



class ApiTest(Base):
    def event(self, method, path, body=None, email=OWNER, verified="true", query=None):
        return {
            "rawPath": path,
            "queryStringParameters": query,
            "requestContext": {"http": {"method": method}, "authorizer": {"jwt": {"claims": {"email": email, "email_verified": verified}}}},
            "body": json.dumps(body) if body is not None else None,
        }

    def call(self, method, path, body=None, email=OWNER, verified="true", query=None):
        result = app.handler(self.event(method, path, body, email, verified, query), None)
        return result["statusCode"], json.loads(result["body"])

    def test_create_with_a_comment_and_a_forwarding_address(self):
        status, created = self.call("POST", "/api/aliases", {"comment": "Bank", "forward_to": " Work@Example.NET "})
        self.assertEqual(status, 201)
        self.assertRegex(created["local"], r"^[a-z]+-[a-z]+-\d{2}$")
        self.assertEqual((created["comment"], created["forward_to"], created["destination"]), ("Bank", "work@example.net", "work@example.net"))
        status, plain = self.call("POST", "/api/aliases", {"comment": ""})
        self.assertEqual(plain["destination"], OWNER, "no address of its own: the default one")

    def test_a_chosen_name(self):
        self.assertEqual(self.call("POST", "/api/aliases", {"local": "Shop.Online"})[1]["address"], f"shop.online@{DOMAIN}")
        self.assertEqual(self.call("POST", "/api/aliases", {"local": "shop.online"})[0], 409)
        self.assertEqual(self.call("POST", "/api/aliases", {"local": "new"})[0], 201, "the old command names are free")
        for bad in ("noreply", "postmaster", "r-abc", "shop_abcdefghijkl", "-x", "a b", "x" * 41):
            self.assertEqual(self.call("POST", "/api/aliases", {"local": bad})[0], 400, bad)

    def test_create_on_the_second_domain(self):
        self.assertEqual(self.call("GET", "/api/me")[1]["domains"], [DOMAIN, OTHER])
        status, created = self.call("POST", "/api/aliases", {"local": "shop", "domain": OTHER.upper()})
        self.assertEqual((status, created["address"], created["domain"]), (201, f"shop@{OTHER}", OTHER))
        self.assertEqual(self.table.items[("ALIAS", "shop")]["domain"], OTHER)
        self.assertEqual(self.call("POST", "/api/aliases", {"local": "shop"})[0], 409, "a name is unique across the domains")
        self.assertNotIn("domain", self.table.items[("ALIAS", self.call("POST", "/api/aliases", {})[1]["local"])], "the first domain is not stored")
        self.assertEqual(self.call("POST", "/api/aliases", {"domain": "other.test"})[1]["code"], "bad_domain")
        self.assertEqual(self.call("POST", "/api/aliases", {"forward_to": f"me@{OTHER}"})[1]["code"], "forward_loop")

    def test_list_change_and_delete(self):
        self.alias("bold-fox-10")
        self.alias("calm-owl-20", forward="work@example.net")
        self.ses.identities.update({OWNER: True, "example.net": True})
        status, listed = self.call("GET", "/api/aliases")
        self.assertEqual(status, 200)
        self.assertEqual({item["local"] for item in listed["items"]}, {"bold-fox-10", "calm-owl-20"})
        self.assertEqual(listed["destinations"], {OWNER: "verified", "work@example.net": "verified"}, "a verified domain covers its addresses")
        self.assertFalse(listed["production"])

        status, changed = self.call("PATCH", "/api/aliases/calm-owl-20", {"comment": "Gym", "forward_to": "", "active": False})
        self.assertEqual((changed["comment"], changed["forward_to"], changed["destination"], changed["active"]), ("Gym", "", OWNER, False))
        self.assertNotIn("forward_to", self.table.items[("ALIAS", "calm-owl-20")])
        self.assertEqual(self.call("PATCH", "/api/aliases/nope", {"comment": "x"})[0], 404)
        self.assertEqual(self.call("PATCH", "/api/aliases/bold-fox-10", {"active": "yes"})[0], 400)
        self.assertEqual(self.call("PATCH", "/api/aliases/bold-fox-10", {"forward_to": f"x@{DOMAIN}"})[0], 400, "no loops")

        self.assertEqual(self.call("DELETE", "/api/aliases/bold-fox-10")[0], 200)
        self.assertNotIn(("ALIAS", "bold-fox-10"), self.table.items)
        self.assertEqual(self.call("DELETE", "/api/aliases/bold-fox-10")[0], 404)

    def test_sender_name(self):
        status, created = self.call("POST", "/api/aliases", {"comment": "Bank", "sender_name": "  Ivan   P. "})
        self.assertEqual((status, created["sender_name"]), (201, "Ivan P."))
        local = created["local"]
        self.assertEqual(self.call("PATCH", f"/api/aliases/{local}", {"sender_name": "Иван"})[1]["sender_name"], "Иван")
        self.assertEqual(self.call("PATCH", f"/api/aliases/{local}", {"sender_name": ""})[1]["sender_name"], "")
        self.assertNotIn("sender_name", self.table.items[("ALIAS", local)], "empty: the name from the message")
        for bad in ("me@example.org", "Ivan <x>", 'Ivan "P"', "a\nb", "x" * 101, 5):
            self.assertEqual(self.call("PATCH", f"/api/aliases/{local}", {"sender_name": bad})[0], 400, bad)

    def test_verify_a_forwarding_address(self):
        status, result = self.call("POST", "/api/destinations", {"address": "New@Example.net"})
        self.assertEqual((status, result), (200, {"address": "new@example.net", "status": "pending"}))
        self.assertEqual(self.ses.verify_requests, ["new@example.net"])
        self.assertEqual(self.call("POST", "/api/destinations", {"address": "nope"})[0], 400)

    def test_find_the_conversation_behind_a_relay_address(self):
        alias = self.alias()
        self.deliver(raw_message("Shop <news@shop.test>", alias), [alias], "news@shop.test")
        relay = self.ses.sent[-1][0]
        expected = {"code": app.relay_code(relay), "relay": relay, "alias": "quiet-river-42", "address": alias, "sender": "news@shop.test", "name": "Shop"}
        for asked in (relay, f"r-{app.relay_code(relay)}@{DOMAIN}", f"R-{app.relay_code(relay).upper()}"):
            self.assertEqual(self.call("GET", f"/api/relays/{asked}"), (200, expected), asked)
        self.assertEqual(self.call("GET", "/api/relays/r-nothingthere")[0], 404)
        self.assertEqual(self.call("GET", "/api/relays/quiet-river-42")[0], 404)

    # Correspondents and new messages
    def test_add_a_correspondent_and_write_to_them_from_the_mail_client(self):
        alias = self.alias("sunny-raven-80", domain=OTHER)
        status, added = self.call("POST", "/api/relays", {"alias": "Sunny-Raven-80", "address": " Sergey.Yugoman@Armenotech.com ", "name": "Sergey"})
        code = app.reply_code("sunny-raven-80", "sergey.yugoman@armenotech.com")
        self.assertEqual(status, 201)
        self.assertEqual(added["relay"], f"sergey_yugoman_at_armenotech_com_{code}@{OTHER}")
        self.assertEqual((added["address"], added["sender"], added["name"]), (alias, "sergey.yugoman@armenotech.com", "Sergey"))
        self.deliver(raw_message(f"Me <{OWNER}>", added["relay"], subject="Hello Sergey", body=f"Hi! Write to me, not to {OWNER}."), [added["relay"]], OWNER)
        source, to, message = self.ses.sent[-1]
        self.assertEqual((source, to), (alias, ["sergey.yugoman@armenotech.com"]), "goes to them from the alias, as a reply would")
        self.assertEqual(message["To"].addresses[0].display_name, "Sergey")
        self.assertNotIn(OWNER, message.get_body(("plain",)).get_content().lower())
        status, listed = self.call("GET", "/api/aliases/sunny-raven-80/relays")
        self.assertEqual((status, [item["relay"] for item in listed["items"]]), (200, [added["relay"]]))
        self.assertEqual(self.call("POST", "/api/relays", {"alias": "sunny-raven-80", "address": "sergey.yugoman@armenotech.com"})[1]["name"], "Sergey", "adding again keeps the name")

    def test_a_correspondent_is_removed_and_its_relay_address_stops(self):
        self.alias()
        relay = self.call("POST", "/api/relays", {"alias": "quiet-river-42", "address": "bob@shop.test"})[1]["relay"]
        self.assertEqual(self.call("DELETE", f"/api/relays/{relay}"), (200, {"deleted": app.relay_code(relay)}))
        self.assertEqual(self.call("DELETE", f"/api/relays/{relay}")[0], 404)
        self.assertEqual(self.call("GET", "/api/aliases/quiet-river-42/relays")[1]["items"], [])
        self.deliver(raw_message(OWNER, relay), [relay], OWNER)
        self.assertEqual(self.ses.sent, [], "an unknown code is dropped")

    def test_a_correspondent_needs_an_alias_and_a_foreign_address(self):
        self.alias()
        self.assertEqual(self.call("POST", "/api/relays", {"alias": "nobody", "address": "bob@shop.test"})[1]["code"], "alias_not_found")
        self.assertEqual(self.call("GET", "/api/aliases/nobody/relays")[0], 404)
        for bad in ("", "bob", "bob@", f"someone@{OTHER}", f"x@{DOMAIN}"):
            self.assertEqual(self.call("POST", "/api/relays", {"alias": "quiet-river-42", "address": bad})[1]["code"], "bad_recipient", bad)
        self.assertEqual(self.call("POST", "/api/relays", {"alias": "quiet-river-42", "address": "bob@shop.test", "name": "Bob <bob@x>"})[1]["code"], "bad_name")

    def test_send_a_new_message_from_an_alias(self):
        alias = self.alias(sender_name="Shop Buyer")
        status, sent = self.call("POST", "/api/messages", {"alias": "quiet-river-42", "to": "Bob@Shop.test", "subject": " Where is my order? ", "text": "Hello,\norder 42 please."})
        self.assertEqual(status, 201)
        source, to, message = self.ses.sent[-1]
        self.assertEqual((source, to), (alias, ["bob@shop.test"]))
        self.assertEqual(self.ses.sources[-1], f"Shop Buyer <{alias}>")
        self.assertEqual(str(message["Subject"]), "Where is my order?")
        self.assertTrue(str(message["Message-ID"]).endswith(f"@{DOMAIN}>"))
        self.assertIn("order 42 please.", message.get_body(("plain",)).get_content())
        code = app.reply_code("quiet-river-42", "bob@shop.test")
        self.assertEqual(sent["relay"], app.relay_address("bob@shop.test", code, DOMAIN))
        self.assertIn(("REPLY", code), self.table.items, "the recipient becomes a correspondent")
        items = self.call("GET", "/api/messages")[1]["items"]
        self.assertEqual((items[0]["id"], items[0]["direction"], items[0]["to_address"], items[0]["subject"]), (sent["id"], "out", "bob@shop.test", "Where is my order?"))
        read = self.call("GET", f"/api/messages/{sent['id']}")[1]
        self.assertIn("order 42 please.", read["text"])
        # Bob answers the alias; the owner carries on from the mail client.
        self.deliver(raw_message("Bob <bob@shop.test>", alias, subject="Re: Where is my order?"), [alias], "bob@shop.test")
        self.assertEqual(self.ses.sent[-1][0], sent["relay"], "the answer comes from the same relay address")

    def test_a_new_message_is_checked_and_a_refused_one_is_not_logged(self):
        self.alias()
        base = {"alias": "quiet-river-42", "to": "bob@shop.test", "subject": "Hi", "text": "Hi"}
        for change, code in (({"alias": "nobody"}, "alias_not_found"), ({"to": f"x@{DOMAIN}"}, "bad_recipient"), ({"subject": "a\r\nBcc: x@y.test"}, "bad_subject"),
                             ({"subject": "x" * 301}, "bad_subject"), ({"text": None}, "bad_text"), ({"text": "x" * 100_001}, "bad_text")):
            self.assertEqual(self.call("POST", "/api/messages", {**base, **change})[1]["code"], code, change)

        class Rejected(Exception):
            response = {"Error": {"Code": "MessageRejected"}}

        def reject(**kwargs):
            raise Rejected()

        self.ses.send_email = reject
        self.assertEqual(self.call("POST", "/api/messages", base), (400, {"error": app.ERRORS["send_rejected"], "code": "send_rejected"}))
        self.assertEqual(self.call("GET", "/api/messages")[1]["items"], [], "nothing went out, nothing is logged")

    def deliver_some(self):
        first, second = self.alias("bold-fox-10"), self.alias("calm-owl-20")
        for number in range(3):
            self.deliver(raw_message(f"Shop <news{number}@shop.test>", first, subject=f"Sale {number}"), [first], f"news{number}@shop.test")
        self.deliver(raw_message("Bank <info@bank.test>", second, subject="Statement"), [second], "info@bank.test")

    def test_list_the_log_newest_first_in_pages(self):
        self.deliver_some()
        app.MESSAGE_PAGE = 3
        self.addCleanup(setattr, app, "MESSAGE_PAGE", 50)
        status, first = self.call("GET", "/api/messages")
        self.assertEqual(status, 200)
        self.assertEqual([item["subject"] for item in first["items"]], ["Statement", "Sale 2", "Sale 1"])
        status, rest = self.call("GET", "/api/messages", query={"cursor": first["cursor"]})
        self.assertEqual(([item["subject"] for item in rest["items"]], rest["cursor"]), (["Sale 0"], ""))
        self.assertEqual(len(self.call("GET", "/api/messages", query={"alias": f"bold-fox-10@{DOMAIN}"})[1]["items"]), 3)
        self.assertEqual([item["subject"] for item in self.call("GET", "/api/messages", query={"q": "BANK"})[1]["items"]], ["Statement"])
        relay = self.ses.sent[0][0]
        for asked in (relay, f"r-{app.relay_code(relay)}@{DOMAIN}"):
            self.assertEqual([item["subject"] for item in self.call("GET", "/api/messages", query={"q": asked})[1]["items"]], ["Sale 0"], asked)

    def test_read_a_message(self):
        alias = self.alias()
        message = email.message.EmailMessage()
        message["From"] = "Shop <news@shop.test>"
        message["To"] = alias
        message["Subject"] = "Привет"
        message.set_content("<html><head><style>p{}</style></head><body><p>Hello&nbsp;<b>you</b></p><script>x()</script><p>Bye</p></body></html>", subtype="html")
        message.add_attachment(b"%PDF", maintype="application", subtype="pdf", filename="bill.pdf")
        self.deliver(message.as_bytes(), [alias], "news@shop.test")
        [listed] = self.call("GET", "/api/messages")[1]["items"]
        status, read = self.call("GET", f"/api/messages/{listed['id']}")
        self.assertEqual(status, 200)
        self.assertEqual(read["text"], "Hello you\n\nBye", "HTML as text, without scripts and styles")
        self.assertEqual(read["headers"]["Subject"], "Привет")
        self.assertEqual(read["attachments"], [{"index": 0, "name": "bill.pdf", "type": "application/pdf", "size": 4, "url": f"/attachments/{listed['id']}/0"}])
        self.assertEqual(self.call("GET", "/api/messages/nope")[0], 404)

    def deliver_with_attachments(self):
        alias = self.alias()
        message = email.message.EmailMessage()
        message["From"] = "Shop <news@shop.test>"
        message["To"] = alias
        message["Subject"] = "Bill"
        message.set_content("See the bill")
        message.add_attachment(b"%PDF-1", maintype="application", subtype="pdf", filename="счёт 1.pdf")
        message.add_attachment(b"<script>x()</script>", maintype="text", subtype="html", filename="page.html")
        self.deliver(message.as_bytes(), [alias], "news@shop.test")
        return self.call("GET", "/api/messages")[1]["items"][0]["id"]

    def test_attachments_are_stored_apart_for_cloudfront(self):
        message_id = self.deliver_with_attachments()
        self.assertEqual(self.table.items[("MSG", message_id)]["attachments"], 2)
        first = self.s3.put[f"attachments/{message_id}/0"]
        self.assertEqual(first["Body"], b"%PDF-1")
        self.assertEqual(first["ContentDisposition"], "attachment; filename=\"____ 1.pdf\"; filename*=UTF-8''%D1%81%D1%87%D1%91%D1%82%201.pdf")
        self.assertEqual(self.s3.put[f"attachments/{message_id}/1"]["ContentType"], "application/octet-stream", "never opened as a page")
        read = self.call("GET", f"/api/messages/{message_id}")[1]
        self.assertEqual([file["url"] for file in read["attachments"]], [f"/attachments/{message_id}/0", f"/attachments/{message_id}/1"])

    def test_older_messages_get_their_attachments_when_read(self):
        message_id = self.deliver_with_attachments()
        del self.table.items[("MSG", message_id)]["attachments"]
        self.s3.objects = {key: value for key, value in self.s3.objects.items() if not key[1].startswith("attachments/")}
        self.call("GET", f"/api/messages/{message_id}")
        self.assertIn(("mail", f"attachments/{message_id}/1"), self.s3.objects)
        self.assertEqual(self.table.items[("MSG", message_id)]["attachments"], 2)

    def test_a_successful_answer_sets_the_signed_cookie(self):
        result = app.handler(self.event("GET", "/api/aliases"), None)
        cookies = dict(cookie.split("; ")[0].split("=", 1) for cookie in result["cookies"])
        self.assertEqual(cookies["CloudFront-Key-Pair-Id"], "K123")
        for cookie in result["cookies"]:
            self.assertIn("Path=/attachments; Secure; HttpOnly; SameSite=Strict; Max-Age=3600", cookie)
        decode = lambda value: base64.b64decode(value.replace("-", "+").replace("_", "=").replace("~", "/"))
        policy = decode(cookies["CloudFront-Policy"])
        [statement] = json.loads(policy)["Statement"]
        self.assertEqual(statement["Resource"], "https://*/attachments/*", "every distribution of the page")
        self.assertGreater(statement["Condition"]["DateLessThan"]["AWS:EpochTime"], time.time() + 3500)
        key = app.load_rsa_private_key(TEST_KEY)
        signed = int.from_bytes(decode(cookies["CloudFront-Signature"]), "big")
        expected = app.SHA1_DIGEST_INFO + hashlib.sha1(policy).digest()
        self.assertTrue(pow(signed, key["e"], key["n"]).to_bytes(128, "big").endswith(b"\x00" + expected), "a valid PKCS#1 v1.5 signature")
        app.handler(self.event("GET", "/api/aliases"), None)
        self.assertEqual(self.ssm.reads, 1, "the key is read once")

    def test_no_cookie_without_a_verified_user_or_on_errors(self):
        self.assertNotIn("cookies", app.handler(self.event("GET", "/api/aliases", verified="false"), None))
        self.assertNotIn("cookies", app.handler(self.event("GET", "/api/nowhere"), None))

    def test_sign_out_clears_the_cookie(self):
        result = app.handler(self.event("DELETE", "/api/session"), None)
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(len(result["cookies"]), 3)
        for cookie in result["cookies"]:
            self.assertRegex(cookie, r"^CloudFront-[A-Za-z-]+=; Path=/attachments; .*Max-Age=0$")

    def test_delete_one_message_or_the_log_of_an_alias(self):
        self.deliver_some()
        items = self.call("GET", "/api/messages")[1]["items"]
        self.assertEqual(self.call("DELETE", f"/api/messages/{items[0]['id']}"), (200, {"deleted": 1}))
        self.assertNotIn(("mail", "messages/" + items[0]["id"]), self.s3.objects)
        self.assertFalse([key for key in self.s3.objects if key[1].startswith("attachments/" + items[0]["id"])])
        self.assertEqual(self.call("DELETE", f"/api/messages/{items[0]['id']}")[0], 404)
        self.assertEqual(self.call("DELETE", "/api/messages", query={"alias": "bold-fox-10"}), (200, {"deleted": 3}))
        self.assertEqual(self.call("GET", "/api/messages")[1]["items"], [])
        self.assertFalse([key for key in self.s3.objects if key[1].startswith("messages/")])
        self.assertTrue([key for key in self.s3.objects if key[1].startswith("incoming/")], "received copies are left to expire")
        self.assertIn(("ALIAS", "bold-fox-10"), self.table.items, "the alias stays")

    # API keys and the addy.io API

    def make_key(self, name="Bitwarden"):
        status, created = self.call("POST", "/api/tokens", {"name": name})
        self.assertEqual(status, 201)
        return created

    def v1(self, method, path, key=None, body=None, headers=None):
        event = {
            "rawPath": "/api/v1" + path,
            "headers": {**({"authorization": f"Bearer {key}"} if key else {}), **(headers or {})},
            "requestContext": {"http": {"method": method}},
            "body": json.dumps(body) if body is not None else None,
        }
        result = app.handler(event, None)
        return result["statusCode"], json.loads(result["body"]) if result["body"] else None, result["headers"]

    def test_a_key_is_shown_once_and_kept_only_as_a_hash(self):
        created = self.make_key()
        self.assertRegex(created["token"], r"^hme[A-Za-z0-9]{48}$")
        # The check of the addy.io browser extension: letters and digits, 40 or more.
        self.assertRegex(created["token"], r"^(addy_io_)?[a-zA-Z0-9]+$")
        self.assertGreaterEqual(len(created["token"]), 40)
        self.assertEqual((created["name"], created["created_by"]), ("Bitwarden", OWNER))
        stored = repr(self.table.items)
        self.assertNotIn(created["token"], stored, "the key itself is not stored")
        self.assertIn(hashlib.sha256(created["token"].encode()).hexdigest(), stored)
        for name in ("one", "two"):
            self.make_key(name)
        listed = self.call("GET", "/api/tokens")[1]["items"]
        self.assertEqual(len(listed), 3, "all pages")
        self.assertNotIn("token", listed[0])
        self.assertEqual(self.call("DELETE", f"/api/tokens/{created['id']}"), (200, {"deleted": created["id"]}))
        self.assertEqual(self.v1("GET", "/aliases", created["token"])[0], 401, "a revoked key stops working")
        self.assertEqual(self.call("DELETE", f"/api/tokens/{created['id']}")[0], 404)
        self.assertEqual(self.call("POST", "/api/tokens", {"name": "x" * 101})[0], 400)

    def test_keys_are_managed_only_with_a_cognito_sign_in(self):
        self.assertEqual(self.call("POST", "/api/tokens", {"name": "x"}, verified="false")[0], 403)

    def test_the_bitwarden_generator_creates_an_alias(self):
        key = self.make_key()["token"]
        status, body, headers = self.v1("POST", "/aliases", key, {"domain": DOMAIN, "description": "Website: shop.test. Generated by Bitwarden."})
        self.assertEqual(status, 201)
        self.assertRegex(body["data"]["email"], rf"^[a-z]+-[a-z]+-\d{{2}}@{re.escape(DOMAIN)}$")
        self.assertEqual(headers["access-control-allow-origin"], "*")
        local = body["data"]["id"]
        self.assertEqual(self.table.items[("ALIAS", local)]["comment"], "Website: shop.test. Generated by Bitwarden.")
        self.assertTrue(self.table.items[("ALIAS", local)]["active"])
        self.assertTrue([item for (pk, _), item in self.table.items.items() if pk == "TOKEN"][0]["last_used_at"])
        alias = body["data"]["email"]
        self.deliver(raw_message("news@shop.test", alias), [alias], "news@shop.test")
        self.assertEqual(self.ses.sent[-1][1], [OWNER], "it works at once")

    def test_list_get_create_custom_and_delete_through_the_addy_api(self):
        key = self.make_key()["token"]
        self.alias("bold-fox-10")
        status, created, _ = self.v1("POST", "/aliases", key, {"domain": DOMAIN, "format": "custom", "local_part": "Shop.Two"})
        self.assertEqual((status, created["data"]["email"]), (201, f"shop.two@{DOMAIN}"))
        status, listed, _ = self.v1("GET", "/aliases", key)
        self.assertEqual({item["id"] for item in listed["data"]}, {"bold-fox-10", "shop.two"})
        self.assertEqual([(each["id"], each["email"]) for each in self.v1("GET", "/aliases/shop.two", key)[1]["data"]["recipients"]], [(OWNER, OWNER)])
        self.assertEqual(self.v1("DELETE", "/aliases/shop.two", key)[:2], (204, None))
        self.assertEqual(self.v1("DELETE", "/aliases/shop.two", key)[0], 404)
        self.assertEqual(self.v1("GET", "/aliases/shop.two", key)[0], 404)
        self.assertEqual(self.v1("POST", "/aliases", key, {"domain": "other.test"})[:2], (422, {"message": "Unknown domain", "code": "bad_domain", "errors": {"bad_domain": ["Unknown domain"]}}))
        self.assertEqual(self.v1("POST", "/aliases", key, {"domain": DOMAIN, "format": "emoji"})[0], 422)
        self.assertEqual(self.v1("POST", "/aliases", key, {"domain": DOMAIN, "format": "custom", "local_part": "noreply"})[0], 400)

    def test_the_addy_api_wants_a_valid_key_and_reaches_nothing_else(self):
        key = self.make_key()["token"]
        for bad in (None, "hme_" + "x" * 43, "not-a-key"):
            status, body, headers = self.v1("GET", "/aliases", bad)
            self.assertEqual((status, body["code"]), (401, "bad_token"), bad)
            self.assertEqual(headers["access-control-allow-origin"], "*")
        self.assertEqual(self.v1("GET", "/aliases", headers={"authorization": f"Basic {key}"})[0], 401)
        for path in ("/messages", "/tokens", "/me", "/../aliases"):
            self.assertEqual(self.v1("GET", path, key)[0], 404, path)
        event = {"rawPath": "/api/aliases", "headers": {"authorization": f"Bearer {key}"}, "requestContext": {"http": {"method": "GET"}}}
        self.assertEqual(app.handler(event, None)["statusCode"], 403, "a key does not open the Cognito API")

    def test_a_key_of_the_older_form_still_works(self):
        old = "hme_" + "A" * 43
        digest = hashlib.sha256(old.encode()).hexdigest()
        self.table.items[("TOKEN", digest)] = {"pk": "TOKEN", "sk": digest, "id": digest[:12], "name": "old"}
        self.assertEqual(self.v1("GET", "/aliases", old)[0], 200)

    def test_the_addy_extension_signs_in_and_loads_its_lists(self):
        key = self.make_key()["token"]
        self.alias("bold-fox-10", forward="work@example.net")
        status, options, _ = self.v1("GET", "/domain-options", key)
        self.assertEqual((status, options["data"], options["defaultAliasDomain"]), (200, [DOMAIN, OTHER], DOMAIN))
        status, created, _ = self.v1("POST", "/aliases", key, {"domain": OTHER, "description": "x"})
        self.assertEqual((status, created["data"]["domain"]), (201, OTHER))
        self.assertEqual(created["data"]["email"], f"{created['data']['local_part']}@{OTHER}")
        self.assertEqual([(each["id"], each["email"]) for each in self.v1("GET", "/recipients", key)[1]["data"]], [(OWNER, OWNER), ("work@example.net", "work@example.net")])
        self.assertEqual(self.v1("GET", "/labels", key)[1], {"data": []})

    def test_the_addy_app_signs_in(self):
        made = self.make_key("Phone")
        key = made["token"]
        self.alias("bold-fox-10", forward="work@example.net")
        self.alias("calm-bay-11")
        self.table.items[("ALIAS", "calm-bay-11")].update(active=False, pinned=True, forwarded=3)
        status, account, headers = self.v1("GET", "/account-details", key)
        self.assertEqual((status, headers["access-control-allow-origin"]), (200, "*"))
        data = account["data"]
        self.assertEqual((data["id"], data["username"], data["default_alias_domain"], data["default_recipient_id"]), (made["id"], OWNER.split("@")[0], DOMAIN, OWNER))
        self.assertEqual((data["total_aliases"], data["total_active_aliases"], data["total_inactive_aliases"], data["total_pinned_aliases"]), (2, 1, 1, 1))
        self.assertEqual((data["total_emails_forwarded"], data["recipient_count"], data["active_domain_count"]), (3, 2, 2))
        self.assertEqual((data["subscription"], data["recipient_limit"], data["bandwidth_limit"]), (None, 0, 0), "self-hosted: no plan, no limits")
        self.assertRegex(data["created_at"], r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$")
        status, token, _ = self.v1("GET", "/api-token-details", key)
        self.assertEqual((status, token["name"], token["expires_at"]), (200, "Phone", None))
        self.assertEqual(token["created_at"], data["created_at"])
        status, version, _ = self.v1("GET", "/app-version", key)
        self.assertEqual((status, version), (200, {"version": app.ADDY_VERSION, "major": 1, "minor": 7, "patch": 3}))
        for path in ("/usernames", "/domains", "/rules", "/failed-deliveries", "/blocklist", "/account-notifications"):
            self.assertEqual(self.v1("GET", path, key)[:2], (200, {"data": []}), path)
        self.assertEqual(self.v1("GET", "/account-details", "not-a-key")[0], 401)

    def assert_ios(self, kind, value):
        for name, kind_type in IOS_REQUIRED[kind].items():
            self.assertIn(name, value, f"{kind}.{name}")
            self.assertIsInstance(value[name], kind_type, f"{kind}.{name}")
            if kind_type is int:
                self.assertNotIsInstance(value[name], bool, f"{kind}.{name}")
        for name in ("created_at", "updated_at", "email_verified_at", "last_forwarded"):
            if value.get(name):
                self.assertRegex(value[name], ADDY_TIME, f"{kind}.{name}")

    def test_the_ios_app_decodes_every_answer(self):
        key = self.make_key("Phone")["token"]
        self.alias("bold-fox-10", forward="work@example.net")
        self.deliver(raw_message("news@shop.test", f"bold-fox-10@{DOMAIN}"), [f"bold-fox-10@{DOMAIN}"], "news@shop.test")
        self.assert_ios("version", self.v1("GET", "/app-version", key)[1])
        account = self.v1("GET", "/account-details", key)[1]["data"]
        self.assert_ios("account", account)
        self.assert_ios("token", self.v1("GET", "/api-token-details", key)[1])
        status, recipient, _ = self.v1("GET", "/recipients/" + account["default_recipient_id"], key)
        self.assertEqual(status, 200, "the splash screen loads the default recipient")
        self.assert_ios("recipient", recipient["data"])
        self.assertEqual(self.v1("GET", "/recipients/nobody@example.net", key)[0], 404)
        for item in self.v1("GET", "/recipients", key)[1]["data"]:
            self.assert_ios("recipient", item)
        page = self.v1("GET", "/aliases", key)[1]
        self.assert_ios("meta", page["meta"])
        for item in page["data"]:
            self.assert_ios("alias", item)
            for each in item["recipients"]:
                self.assert_ios("recipient", each)
        self.assertTrue(page["data"][0]["last_forwarded"])
        created = self.v1("POST", "/aliases", key, {"domain": DOMAIN, "description": "x"})[1]["data"]
        self.assert_ios("alias", created)
        self.assert_ios("alias", self.v1("GET", "/aliases/bold-fox-10", key)[1]["data"])

    def extension_list(self, key, **params):
        query = {"filter[deleted]": "without", "filter[active]": "", "filter[pinned]": "", "filter[search]": "", "sort": "-created_at",
                 "page[number]": "1", "page[size]": "10", "with": "labels"}
        query.update(params)
        event = {"rawPath": "/api/v1/aliases", "headers": {"authorization": f"Bearer {key}"}, "requestContext": {"http": {"method": "GET"}},
                 "queryStringParameters": query}
        return json.loads(app.handler(event, None)["body"])

    def test_the_addy_extension_lists_filters_sorts_and_pages(self):
        key = self.make_key()["token"]
        for number in range(12):
            self.alias(f"name-{number:02d}", active=number % 3 != 0)
            self.table.items[("ALIAS", f"name-{number:02d}")]["created_at"] = f"2026-10-{number + 1:02d}T00:00:00Z"
        self.table.items[("ALIAS", "name-05")]["comment"] = "Shop Online"
        first = self.extension_list(key)
        self.assertEqual([item["id"] for item in first["data"]][:2], ["name-11", "name-10"], "newest first")
        self.assertEqual((len(first["data"]), first["meta"]["total"], bool(first["links"]["next"])), (10, 12, True))
        second = self.extension_list(key, **{"page[number]": "2"})
        self.assertEqual(([item["id"] for item in second["data"]], second["links"]["next"]), (["name-01", "name-00"], None))
        self.assertEqual(self.extension_list(key, **{"filter[active]": "false"})["meta"]["total"], 4)
        self.assertEqual([item["id"] for item in self.extension_list(key, **{"filter[search]": "ONLINE"})["data"]], ["name-05"])
        self.assertEqual(self.extension_list(key, **{"filter[deleted]": "only"})["data"], [])
        self.assertEqual(self.extension_list(key, sort="created_at")["data"][0]["id"], "name-00")
        item = first["data"][0]
        for field in ("labels", "extension", "deleted_at", "pinned", "last_forwarded", "emails_blocked"):
            self.assertIn(field, item)

    def test_the_addy_extension_creates_edits_toggles_and_pins(self):
        key = self.make_key()["token"]
        body = {"domain": DOMAIN, "local_part": "", "description": "shop.test", "format": "random_characters", "recipient_ids": ["work@example.net"], "label_ids": []}
        status, created, _ = self.v1("POST", "/aliases", key, body)
        self.assertEqual(status, 201)
        alias = created["data"]
        self.assertEqual(f"{alias['local_part']}@{alias['domain']}", alias["email"], "formatAliasEmail of the extension")
        self.assertEqual(self.table.items[("ALIAS", alias["id"])]["forward_to"], "work@example.net", "the chosen recipient")
        local = alias["id"]
        self.assertEqual(self.v1("PATCH", f"/aliases/{local}", key, {"description": "Shop"})[1]["data"]["description"], "Shop")
        self.assertEqual(self.v1("DELETE", f"/active-aliases/{local}", key)[0], 204)
        self.assertFalse(self.table.items[("ALIAS", local)]["active"])
        self.assertEqual(self.v1("POST", "/active-aliases", key, {"id": local})[1]["data"]["active"], True)
        self.assertEqual(self.v1("POST", "/pinned-aliases", key, {"id": local})[1]["data"]["pinned"], True)
        self.assertEqual(self.v1("DELETE", f"/pinned-aliases/{local}", key)[0], 204)
        self.assertFalse(self.table.items[("ALIAS", local)]["pinned"])
        self.assertEqual(self.v1("POST", "/alias-labels", key, {"alias_id": local, "label_ids": ["x"]})[1]["data"]["labels"], [])
        self.assertEqual(self.v1("POST", "/active-aliases", key, {"id": "nope"})[0], 404)
        status, error, _ = self.v1("POST", "/aliases", key, {"domain": "other.test"})
        self.assertEqual((status, error["errors"]), (422, {"bad_domain": ["Unknown domain"]}), "the extension shows errors[first][0]")

    def test_a_preflight_needs_no_key(self):
        status, body, headers = self.v1("OPTIONS", "/aliases")
        self.assertEqual((status, body), (204, None))
        self.assertIn("Authorization", headers["access-control-allow-headers"])
        self.assertIn("X-Requested-From", headers["access-control-allow-headers"], "sent by the addy.io extension")
        self.assertIn("PATCH", headers["access-control-allow-methods"])

    # Without mail (the demo)

    def test_without_mail_nothing_asks_ses(self):
        os.environ["MAIL_ENABLED"] = "false"
        self.addCleanup(os.environ.pop, "MAIL_ENABLED")
        self.ses.get_email_identity = self.ses.get_account = None
        self.alias("bold-fox-10", forward="work@example.net")
        me = self.call("GET", "/api/me")[1]
        self.assertEqual((me["mail"], me["production"]), (False, False))
        listed = self.call("GET", "/api/aliases")[1]
        self.assertEqual(listed["destinations"], {OWNER: "none", "work@example.net": "none"})
        self.assertEqual(self.call("POST", "/api/destinations", {"address": "a@example.net"})[1]["code"], "mail_disabled")

    def test_caps_of_the_installation(self):
        os.environ.update(MAX_ALIASES="2", MAX_TOKENS="1")
        self.addCleanup(lambda: [os.environ.pop(name) for name in ("MAX_ALIASES", "MAX_TOKENS")])
        self.assertEqual(self.call("POST", "/api/aliases", {})[0], 201)
        self.assertEqual(self.call("POST", "/api/aliases", {})[0], 201)
        self.assertEqual(self.call("POST", "/api/aliases", {}), (429, {"error": "The limit of this installation is reached; delete something first", "code": "limit_reached"}))
        self.assertEqual(self.call("POST", "/api/tokens", {"name": "a"})[0], 201)
        self.assertEqual(self.call("POST", "/api/tokens", {"name": "b"})[0], 429)

    def test_without_mail_correspondents_are_kept_but_nothing_is_sent(self):
        os.environ["MAIL_ENABLED"] = "false"
        self.addCleanup(os.environ.pop, "MAIL_ENABLED")
        self.alias()
        status, added = self.call("POST", "/api/relays", {"alias": "quiet-river-42", "address": "bob@shop.test"})
        self.assertEqual((status, added["sender"]), (201, "bob@shop.test"))
        self.assertEqual(self.call("POST", "/api/messages", {"alias": "quiet-river-42", "to": "ann@shop.test", "subject": "Hi", "text": "Hi"})[1]["code"], "mail_disabled")
        self.assertEqual(self.ses.sent, [])
        self.assertEqual([item["sender"] for item in self.call("GET", "/api/aliases/quiet-river-42/relays")[1]["items"]], ["bob@shop.test"], "a refused message makes no correspondent")

    def test_correspondents_have_a_cap_too(self):
        os.environ["MAX_RELAYS"] = "1"
        self.addCleanup(os.environ.pop, "MAX_RELAYS")
        self.alias()
        self.assertEqual(self.call("POST", "/api/relays", {"alias": "quiet-river-42", "address": "bob@shop.test"})[0], 201)
        self.assertEqual(self.call("POST", "/api/relays", {"alias": "quiet-river-42", "address": "ann@shop.test"})[1]["code"], "limit_reached")

    def test_only_verified_emails_get_in(self):
        self.assertEqual(self.call("GET", "/api/aliases", verified="false")[0], 403)
        self.assertEqual(self.call("GET", "/api/me")[1]["forward_to"], OWNER)
        self.assertEqual(self.call("GET", "/api/nowhere")[0], 404)


GPG = shutil.which("gpg")
try:
    import cryptography  # noqa: F401  the Lambda layer has it
    CRYPTOGRAPHY = True
except ImportError:
    CRYPTOGRAPHY = False
try:
    import cryptography  # noqa: F401  the Lambda layer has it
    CRYPTOGRAPHY = True
except ImportError:
    CRYPTOGRAPHY = False


# The signed part and the signature of a multipart/signed message, cut out of
# its bytes exactly as a mail client does (RFC 3156).
def signed_parts(raw):
    head, body = raw.split(b"\r\n\r\n", 1)
    boundary = re.search(rb'boundary="([^"]+)"', head).group(1)
    first = body.index(b"--" + boundary + b"\r\n") + len(boundary) + 4
    middle = body.index(b"\r\n--" + boundary + b"\r\n", first)
    signature_part = body[middle + len(boundary) + 6:body.index(b"\r\n--" + boundary + b"--")]
    return body[first:middle], signature_part.split(b"\r\n\r\n", 1)[1]


@unittest.skipUnless(CRYPTOGRAPHY, "needs the cryptography package")
@unittest.skipUnless(CRYPTOGRAPHY, "needs the cryptography package of the Lambda layer")
class SignatureTest(Base):
    event = ApiTest.event
    call = ApiTest.call

    def setUp(self):
        super().setUp()
        self.home = tempfile.mkdtemp(prefix="hme-gpg-")
        self.addCleanup(shutil.rmtree, self.home, True)

    def gpg(self, *args, data=None):
        result = subprocess.run([GPG, "--homedir", self.home, "--batch", "--status-fd", "1", *args], input=data, capture_output=True)
        return result.returncode, result.stdout.decode(errors="replace")

    def wkd(self, path, site, local=None):
        result = app.handler({
            "rawPath": "/.well-known/openpgpkey/" + path,
            "requestContext": {"http": {"method": "GET"}},
            "headers": {"X-Hide-My-Email-Site": site} if site else {},
            "queryStringParameters": {"l": local} if local else None,
        }, None)
        body = base64.b64decode(result["body"]) if result.get("isBase64Encoded") else result["body"]
        return result["statusCode"], result["headers"], body

    # The key as a mail client finds it: by the hash of the local part on the
    # domain of the address.
    def verify(self, raw, address):
        local, domain = address.split("@")
        status, headers, key = self.wkd("hu/" + app.pgp.wkd_hash(local), domain, local)
        self.assertEqual((status, headers["Content-Type"]), (200, "application/octet-stream"))
        self.assertEqual(self.gpg("--import", data=key)[0], 0)
        part, signature = signed_parts(raw)
        path = os.path.join(self.home, "part")
        with open(path, "wb") as handle:
            handle.write(part)
        status, out = self.gpg("--verify", "-", path, data=signature)
        self.assertEqual(status, 0, out)
        self.assertIn("GOODSIG", out)
        self.assertIn(address, out)
        return email.message_from_bytes(part, policy=email.policy.default)

    @unittest.skipUnless(GPG, "gpg is not installed")
    def test_a_reply_is_signed_and_its_key_is_found_by_wkd(self):
        alias = self.alias("sunny-raven-80", domain=OTHER)
        self.deliver(raw_message("Bob <bob@shop.test>", alias), [alias], "bob@shop.test")
        relay = self.ses.sent[-1][0]
        text = "Спасибо, Боб!   \n" + "длинная строка " * 40 + "\nFrom here on it is fine.\n"
        self.deliver(raw_message(f"Me <{OWNER}>", relay, subject="Re: Hello", body=text), [relay], OWNER)
        raw = self.ses.raw[-1]
        message = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertEqual((message.get_content_type(), message.get_param("protocol"), message.get_param("micalg")), ("multipart/signed", "application/pgp-signature", "pgp-sha256"))
        self.assertEqual(str(message["Subject"]), "Re: Hello")
        part = self.verify(raw, alias)
        self.assertIn(part["Content-Transfer-Encoding"], ("quoted-printable", "base64"), "safe from re-encoding on the way")
        self.assertEqual(part.get_content(), text.replace("\n", "\n"))
        self.assertTrue(all(byte < 128 for byte in raw), "seven-bit throughout")

    @unittest.skipUnless(GPG, "gpg is not installed")
    def test_forwarded_mail_is_signed_by_its_relay_address(self):
        alias = self.alias("sunny-raven-80", domain=OTHER)
        self.deliver(raw_message("Bob <bob@shop.test>", alias, body="Привет!  \nFrom the shop.\n"), [alias], "bob@shop.test")
        relay, _, message = self.ses.sent[-1]
        self.assertEqual(message.get_content_type(), "multipart/signed")
        self.assertEqual(message["From"].addresses[0].addr_spec, relay)
        part = self.verify(self.ses.raw[-1], relay)
        self.assertEqual(part.get_content().replace("\r\n", "\n"), "Привет!  \nFrom the shop.\n", "trailing spaces and From kept")
        local = relay.split("@")[0]
        name = "hu/" + app.pgp.wkd_hash(local)
        self.assertEqual(self.wkd(name, OTHER)[0], 200, "found by the hash alone too")
        self.assertEqual(self.wkd(name, DOMAIN, local)[0], 404, "the relay lives on the other domain")
        self.assertEqual(self.wkd(name, OTHER, "x" + local)[0], 404, "a made-up name with the same code")
        self.assertNotEqual(self.wkd(name, OTHER)[2], self.wkd("hu/" + app.pgp.wkd_hash("sunny-raven-80"), OTHER)[2], "a key of its own")

    @unittest.skipUnless(GPG, "gpg is not installed")
    def test_a_signed_message_is_forwarded_with_its_own_signature_intact(self):
        alias = self.alias()
        inner = (
            b'Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="in"\r\n'
            b"\r\n--in\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
            + "Подписано отправителем \r\n".encode()
            + b"--in\r\nContent-Type: application/pgp-signature\r\n\r\n-----BEGIN PGP SIGNATURE-----\r\n\r\nxx\r\n-----END PGP SIGNATURE-----\r\n--in--\r\n"
        )
        raw = b"From: Bob <bob@shop.test>\r\nTo: " + alias.encode() + b"\r\nSubject: Signed\r\nMIME-Version: 1.0\r\n" + inner
        self.deliver(raw, [alias], "bob@shop.test")
        relay = self.ses.sent[-1][0]
        part = self.verify(self.ses.raw[-1], relay)
        self.assertEqual(part.get_content_type(), "multipart/signed")
        self.assertEqual(part.get_payload()[0]["Content-Transfer-Encoding"], "8bit", "the sender's part as it was")

    @unittest.skipUnless(GPG, "gpg is not installed")
    def test_a_new_message_is_signed_and_logged_signed(self):
        alias = self.alias(sender_name="Shop Buyer")
        sent = self.call("POST", "/api/messages", {"alias": "quiet-river-42", "to": "bob@shop.test", "subject": "Hi", "text": "Hello, Bob."})[1]
        self.verify(self.ses.raw[-1], alias)
        self.assertEqual(self.s3.objects[("mail", "messages/" + sent["id"])], self.ses.raw[-1], "the log keeps what was sent")
        self.assertIn("Hello, Bob.", self.call("GET", f"/api/messages/{sent['id']}")[1]["text"])

    def test_the_directory_answers_for_its_own_domain_only(self):
        self.alias("sunny-raven-80", domain=OTHER)
        name = "hu/" + app.pgp.wkd_hash("sunny-raven-80")
        status, headers, body = self.wkd("policy", OTHER)
        self.assertEqual((status, body, headers["Access-Control-Allow-Origin"]), (200, "", "*"))
        self.assertEqual(self.wkd(name, OTHER, "sunny-raven-80")[0], 200)
        self.assertEqual(self.wkd(name, OTHER)[0], 200, "found by the hash alone too")
        self.assertEqual(self.wkd(name, DOMAIN, "sunny-raven-80")[0], 404, "the alias lives on the other domain")
        self.assertEqual(self.wkd("hu/" + app.pgp.wkd_hash("nobody"), OTHER, "nobody")[0], 404)
        first = self.wkd(name, OTHER)[2]
        app._pgp_secret = None
        self.assertEqual(self.wkd(name, OTHER)[2], first, "the same key every time")
        self.assertIn("pgp_created", self.table.items[("ALIAS", "sunny-raven-80")])

    def test_the_page_shows_the_key(self):
        self.alias()
        status, key = self.call("GET", "/api/aliases/quiet-river-42/key")
        self.assertEqual(status, 200)
        self.assertRegex(key["fingerprint"], r"^[0-9A-F]{40}$")
        self.assertEqual(key["user_id"], f"quiet-river-42@{DOMAIN}")
        self.assertTrue(key["key"].startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        self.assertEqual(key["wkd"], f"https://{DOMAIN}/.well-known/openpgpkey/hu/{app.pgp.wkd_hash('quiet-river-42')}?l=quiet-river-42")
        self.assertEqual(self.call("GET", "/api/aliases/quiet-river-42/key")[1]["fingerprint"], key["fingerprint"])
        self.assertEqual(self.call("GET", "/api/aliases/nobody/key")[0], 404)
        os.environ["MAIL_ENABLED"] = "false"
        self.addCleanup(os.environ.pop, "MAIL_ENABLED", None)
        self.assertEqual(self.call("GET", "/api/aliases/quiet-river-42/key")[1]["wkd"], f"/.well-known/openpgpkey/hu/{app.pgp.wkd_hash('quiet-river-42')}?l=quiet-river-42", "the demo page is elsewhere")
        self.assertEqual(self.wkd("hu/" + app.pgp.wkd_hash("quiet-river-42"), None, "quiet-river-42")[0], 200, "no domain header: the domain of the aliases")

    def test_the_page_turns_the_signatures_off(self):
        alias = self.alias("sunny-raven-80", domain=OTHER)
        self.deliver(raw_message("bob@shop.test", alias), [alias], "bob@shop.test")
        relay = self.ses.sent[-1][0]
        self.assertEqual(self.call("GET", "/api/me")[1]["pgp"], {"signing": True}, "on until turned off")
        self.assertEqual(self.call("PUT", "/api/settings/pgp", {"signing": "no"})[0], 400)
        self.assertEqual(self.call("PUT", "/api/settings/pgp", {"signing": False}), (200, {"signing": False}))
        self.assertEqual(self.call("GET", "/api/me")[1]["pgp"], {"signing": False})
        self.deliver(raw_message("bob@shop.test", alias), [alias], "bob@shop.test")
        self.assertEqual(self.ses.sent[-1][2].get_content_type(), "text/plain", "forwarded unsigned")
        self.deliver(raw_message(OWNER, relay, subject="Re: Hello"), [relay], OWNER)
        self.assertEqual(self.ses.sent[-1][2].get_content_type(), "text/plain", "no signature.asc")
        self.call("POST", "/api/messages", {"alias": "sunny-raven-80", "to": "bob@shop.test", "subject": "Hi", "text": "Hello, Bob."})
        self.assertEqual(self.ses.sent[-1][2].get_content_type(), "text/plain")
        self.assertEqual(self.call("GET", "/api/aliases/sunny-raven-80/key")[0], 404, "the page shows no key")
        name = "hu/" + app.pgp.wkd_hash("sunny-raven-80")
        status, _, key = self.wkd(name, OTHER)
        self.assertEqual(status, 200, "the directory stays for the mail already signed")
        self.call("PUT", "/api/settings/pgp", {"signing": True})
        self.call("POST", "/api/messages", {"alias": "sunny-raven-80", "to": "bob@shop.test", "subject": "Hi", "text": "Hello again."})
        self.assertEqual(self.ses.sent[-1][2].get_content_type(), "multipart/signed")
        self.assertEqual(self.wkd(name, OTHER)[2], key, "the same key after all")

    def test_without_pgp_there_is_none_of_it(self):
        alias = self.alias("sunny-raven-80", domain=OTHER)
        os.environ["PGP"] = "false"
        self.addCleanup(os.environ.pop, "PGP", None)
        self.assertIsNone(self.call("GET", "/api/me")[1]["pgp"])
        self.assertEqual(self.call("PUT", "/api/settings/pgp", {"signing": True})[0], 404)
        self.call("POST", "/api/messages", {"alias": "sunny-raven-80", "to": "bob@shop.test", "subject": "Hi", "text": "Hello, Bob."})
        self.assertEqual(self.ses.sent[-1][2].get_content_type(), "text/plain")
        self.assertEqual(self.call("GET", "/api/aliases/sunny-raven-80/key")[0], 404)
        self.assertEqual(self.wkd("policy", OTHER)[0], 404)
        self.assertEqual(self.wkd("hu/" + app.pgp.wkd_hash("sunny-raven-80"), OTHER)[0], 404)
        self.assertNotIn("pgp_created", self.table.items[("ALIAS", "sunny-raven-80")], "no key made")
        self.assertIn(alias, self.ses.sent[-1][2]["From"])

    def test_a_reply_goes_out_even_if_signing_fails(self):
        alias = self.alias()
        self.deliver(raw_message("bob@shop.test", alias), [alias], "bob@shop.test")
        relay = self.ses.sent[-1][0]

        def broken(*args):
            raise RuntimeError("no layer")

        real = app.pgp.SigningKey
        app.pgp.SigningKey = broken
        self.addCleanup(setattr, app.pgp, "SigningKey", real)
        self.deliver(raw_message(OWNER, relay, subject="Re: Hello"), [relay], OWNER)
        self.assertEqual(self.ses.sent[-1][1], ["bob@shop.test"])
        self.assertEqual(self.ses.sent[-1][2].get_content_type(), "text/plain")


FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <updated>2026-10-14T09:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/Tozapid/Example/releases/tag/v1.10.0"/>
    <title>v1.10.0 — 2026-10-14 — versions</title>
    <content type="html">&lt;h3&gt;Added&lt;/h3&gt;
&lt;ul&gt;
&lt;li&gt;Settings → &lt;code&gt;Version&lt;/code&gt; shows the &lt;a href="x"&gt;releases&lt;/a&gt;.&lt;/li&gt;
&lt;li&gt;Two&lt;/li&gt;
&lt;/ul&gt;</content>
  </entry>
  <entry>
    <updated>2026-10-13T09:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/Tozapid/Example/releases/tag/nightly"/>
    <title>nightly</title>
  </entry>
  <entry>
    <updated>2026-10-12T09:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/Tozapid/Example/releases/tag/v1.9.0"/>
    <title>v1.9.0 — 2026-10-12</title>
  </entry>
  <entry>
    <updated>2026-10-13T08:00:00Z</updated>
    <link rel="alternate" type="text/html" href="https://github.com/Tozapid/Example/releases/tag/v1.9.1"/>
    <title>v1.9.1 — 2026-10-13 — a fix</title>
  </entry>
</feed>""".encode()


class FakeFeed:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.body


# The releases of the demo repository from the Atom feed of GitHub, without
# GitHub: urlopen is replaced.
class VersionTest(Base):
    event = ApiTest.event
    call = ApiTest.call

    def setUp(self):
        super().setUp()
        self.saved = {name: os.environ.get(name) for name in ("VERSION", "RELEASES_REPOSITORY")}
        os.environ.update(VERSION="v1.9.0", RELEASES_REPOSITORY="Tozapid/Example")
        self.urls = []
        self.feed = FEED
        real = app.urllib.request.urlopen
        app.urllib.request.urlopen = self.urlopen
        self.addCleanup(setattr, app.urllib.request, "urlopen", real)
        app._releases = None
        self.addCleanup(setattr, app, "_releases", None)

    def tearDown(self):
        super().tearDown()
        for name, value in self.saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value

    def urlopen(self, request, timeout=None):
        self.urls.append(request.full_url)
        if isinstance(self.feed, Exception):
            raise self.feed
        return FakeFeed(self.feed)

    def test_the_releases_after_this_version_newest_first(self):
        status, info = self.call("GET", "/api/version")
        self.assertEqual(status, 200)
        self.assertEqual(self.urls, ["https://github.com/Tozapid/Example/releases.atom"])
        self.assertEqual((info["version"], info["repository"], info["latest"], info["error"]), ("v1.9.0", "Tozapid/Example", "v1.10.0", None))
        self.assertEqual(info["url"], "https://github.com/Tozapid/Example/releases")
        self.assertEqual([release["version"] for release in info["newer"]], ["v1.10.0", "v1.9.1"], "by number, not by text; no tag without a version")
        newest = info["newer"][0]
        self.assertEqual((newest["title"], newest["date"], newest["url"]), ("v1.10.0 — 2026-10-14 — versions", "2026-10-14", "https://github.com/Tozapid/Example/releases/tag/v1.10.0"))
        self.assertEqual(newest["notes"], "Added\n• Settings → Version shows the releases.\n• Two")
        self.assertTrue(info["checked_at"].endswith("Z"))

    def test_the_newest_version_has_nothing_newer(self):
        os.environ["VERSION"] = "v1.10.0"
        info = app.version_info()
        self.assertEqual((info["latest"], info["newer"]), ("v1.10.0", []))

    def test_the_list_stays_an_hour(self):
        app.version_info()
        app.version_info()
        self.assertEqual(len(self.urls), 1)
        repository, read_at, releases, checked_at = app._releases
        app._releases = (repository, read_at - app.RELEASES_SECONDS - 1, releases, checked_at)
        app.version_info()
        self.assertEqual(len(self.urls), 2)

    def test_without_github_the_last_list_serves(self):
        self.feed = OSError("no network")
        info = app.version_info()
        self.assertEqual((info["version"], info["error"], info["newer"]), ("v1.9.0", "unavailable", []))
        self.feed = FEED
        app.version_info()
        repository, read_at, releases, checked_at = app._releases
        app._releases = (repository, read_at - app.RELEASES_SECONDS - 1, releases, checked_at)
        self.feed = b"<html>not a feed"
        info = app.version_info()
        self.assertEqual((info["error"], info["latest"], info["checked_at"]), (None, "v1.10.0", checked_at))

    def test_without_a_repository_nothing_is_asked(self):
        os.environ["RELEASES_REPOSITORY"] = ""
        info = app.version_info()
        self.assertEqual((info["version"], info["url"], info["latest"], info["error"]), ("v1.9.0", None, None, None))
        self.assertEqual(self.urls, [])


if __name__ == "__main__":
    unittest.main()
