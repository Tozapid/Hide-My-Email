"""Hide My Email: addresses on own domains that forward to personal addresses.

One function serves both sides. With MAIL_ENABLED off (the public demo) there
is no mail at all: SES neither delivers nor is asked about addresses, and the
API manages aliases, keys, correspondents and the message log only, and no
new message goes out. MAX_ALIASES, MAX_TOKENS and MAX_RELAYS cap what
visitors of the demo can create.

Mail. SES stores every message for the alias domains in S3 and then invokes
the function with the receipt. Each recipient is handled on its own:

- an active alias (quiet-river-42@domain): the message is forwarded to the
  alias's own forwarding address, or to FORWARD_TO when it has none. From
  becomes a relay address with the sender's address in it, as Apple does
  (office_at_shop_test_<code>@domain), so that a reply comes back here; the
  code is kept in DynamoDB with the original sender. r-<code>@domain, the
  older form, still works;
- a relay address, sent from the address the alias forwards to: the reply
  goes to the original sender from the alias, with that address taken out of
  the text.

Everything SES sends is signed: replies and new messages carry an OpenPGP
signature (PGP/MIME, RFC 3156) by the alias's own Ed25519 key (pgp.py),
forwarded mail one by the key of the relay address it comes from. Each key is
published in the Web Key Directory of the alias domain:
/.well-known/openpgpkey/hu/<hash> on the page of each domain, which CloudFront
passes here, so that mail clients find it by the address and check the
signature. The private key is never stored: its seed is derived from the
secret in PGP_SECRET_PARAMETER and the alias, the alias keeps only the time
the key was made (pgp_created), which fixes the fingerprint. The key has no
expiry and goes with the alias. The page can stop the signatures (SETTING
pgp); PGP=false turns all of it off, the directory too.

A conversation may also start here. The page adds a correspondent to an
alias, which makes the relay address of the pair without a message from
them: mail to it from the forwarding address goes to them from the alias, as
a reply would. The page also sends a new text message from an alias, and the
recipient becomes a correspondent of it.

Aliases live on one or more domains: DOMAIN, which is also the page, and the
others in DOMAINS. A local part is unique across them: an alias belongs to
one domain, DOMAIN unless it names another, and mail to the same name on
another domain is dropped. Aliases are managed on the page and through the
API only. Anything else is dropped. A sender counts only when SES saw DMARC
pass, or SPF pass for the same address when its domain has no DMARC record.

Every forwarded message and every reply goes to the message log: a record in
DynamoDB, a copy of the original under MESSAGES_PREFIX in the mail bucket and
each attachment under ATTACHMENTS_PREFIX. Only the page deletes them; the
received copies under MAIL_PREFIX expire. CloudFront serves the attachments
at /attachments/* to whoever holds the signed cookie the API sets.

API. The web page calls /api/... through API Gateway with a Cognito token:
list, create, change and delete aliases, ask SES to verify a forwarding
address while the account is in the SES sandbox, find the conversation behind
a relay address, list, add and remove the correspondents of an alias, send a
new message from an alias, read and delete the message log, manage API keys,
turn the PGP signatures on and off.

/api/v1/aliases is the part of the addy.io API that the username generator
of Bitwarden and the addy.io browser extension use. API Gateway lets it
through without a Cognito token; the function itself wants an API key made on
the page.

DynamoDB: pk = ALIAS, sk = local part (domain, comment, forward_to,
sender_name, active, pinned, created_at, updated_at, forwarded, last_at,
pgp_created);
pk = TOKEN, sk = SHA-256 of an API key (id, name, created_by, created_at,
last_used_at); pk = REPLY, sk = code (alias, sender, name); pk = MSG, sk = id,
which sorts by time (direction, alias, alias_domain, code, relay, from_*,
to_*, delivered_to, subject, at, size, spam, attachments); pk = SETTING,
sk = pgp (signing, updated_at).
"""

import base64
import email
import email.message
import email.policy
import email.utils
import hashlib
import hmac
import html.parser
import json
import logging
import os
import quopri
import re
import secrets
import string
import time
import urllib.request
from datetime import datetime, timezone
from urllib.parse import quote, unquote

import pgp

logger = logging.getLogger()
logger.setLevel(logging.INFO)

REPLY_PREFIX = "r-"
# Keys are letters and digits only, at least 40: the addy.io browser extension
# refuses anything else. Keys made before were hme_ and URL-safe characters;
# they still work, the extension just cannot take them.
TOKEN_PREFIX = "hme"
# The addy.io server version /api/v1/app-version reports. The addy.io apps
# refuse a self-hosted server older than they need (MINIMUMVERSIONCODE in
# AddyIo.swift and AddyIo.kt: 1.7.3); raise it when a newer app asks for more
# and still works with this API. 9999 would mean app.addy.io itself.
ADDY_VERSION = "1.7.3"
TOKEN_ALPHABET = string.ascii_letters + string.digits
# The addy.io API is called from Bitwarden's web vault and extension, other
# origins. It takes a key in a header, never a cookie, so any origin may call.
CORS_HEADERS = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "access-control-allow-headers": "Authorization, Content-Type, Accept, X-Requested-With, X-Requested-From",
    "access-control-max-age": "86400",
}
CODE_LENGTH = 12
# A relay address: the sender's address in the local part, "_", the code.
RELAY_RE = re.compile(rf"^[a-z0-9_]+_([a-z2-7]{{{CODE_LENGTH}}})$")
MESSAGE_PAGE = 50
# A new message from the page: a subject on one line and plain text.
SUBJECT_LIMIT = 300
TEXT_LIMIT = 100_000
# The request with such a text, room left for JSON escapes.
MESSAGE_BODY_LIMIT = 4 * TEXT_LIMIT
# How long the signed cookie for /attachments/* lasts; every successful API
# answer renews it.
COOKIE_SECONDS = 3600
# DER prefix of a SHA-1 DigestInfo for PKCS#1 v1.5 signatures.
SHA1_DIGEST_INFO = bytes.fromhex("3021300906052b0e03021a05000414")
# Names that are not given out as aliases: the usual role addresses.
RESERVED = {"noreply", "postmaster", "abuse", "hostmaster", "webmaster", "bounce", "mailer-daemon"}
ALIAS_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,38}[a-z0-9])?$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
# Headers that name an address SES would have to send for, or that speak of
# the checks of the original message (its signature, SPF, ARC, the receipt by
# SES). Left in a forwarded message they contradict the new From and its DKIM,
# which Gmail takes for spoofing; left in a reply they show the personal
# address (smtp.mailfrom=me@…).
DROPPED_HEADERS = (
    "Return-Path", "Sender", "DKIM-Signature", "DomainKey-Signature",
    "Authentication-Results", "Received-SPF", "X-Original-Authentication-Results", "X-Received",
)
DROPPED_PREFIXES = ("ARC-", "X-SES-", "X-Google-", "X-Gm-", "X-MS-Exchange-Organization-")
# A reply also loses the trace of how it left the owner's mailbox: the hosts,
# and with some providers the owner's IP address.
REPLY_DROPPED_HEADERS = ("Received", "X-Originating-IP", "X-Mailer-IP")

ADJECTIVES = (
    "amber", "bold", "brave", "bright", "brisk", "calm", "clever", "cool", "crisp", "daring",
    "eager", "early", "fair", "fancy", "fast", "fresh", "gentle", "glad", "golden", "grand",
    "green", "happy", "honest", "humble", "jolly", "keen", "kind", "late", "lively", "lucky",
    "mellow", "merry", "mild", "misty", "modest", "noble", "polite", "proud", "quick", "quiet",
    "rapid", "rare", "ready", "royal", "rustic", "silent", "silver", "simple", "sleek", "smart",
    "snowy", "solid", "steady", "sunny", "swift", "tidy", "true", "vivid", "warm", "wild",
    "wise", "witty", "young", "zesty",
)
NOUNS = (
    "anchor", "apple", "arrow", "badger", "beacon", "birch", "breeze", "brook", "cactus", "canyon",
    "cedar", "cliff", "cloud", "comet", "coral", "crane", "delta", "dune", "eagle", "ember",
    "falcon", "fern", "field", "fjord", "forest", "fox", "garden", "glacier", "harbor", "hawk",
    "heron", "hill", "island", "lake", "lantern", "maple", "meadow", "moon", "moss", "nest",
    "oak", "ocean", "orchid", "otter", "owl", "pebble", "pine", "planet", "prairie", "rain",
    "raven", "reef", "river", "rock", "sail", "shore", "sky", "spruce", "star", "stone",
    "summit", "tide", "valley", "willow",
)

_s3 = None
_ses = None
_ses_v1 = None
_table = None
_ssm = None
_signing_key = None
_pgp_secret = None


# Errors of the API: a code, which the page translates, and an English text.
ERRORS = {
    "alias_exists": "This address already exists",
    "alias_not_found": "Address not found",
    "not_found": "Not found",
    "bad_active": "active must be true or false",
    "bad_signing": "signing must be true or false",
    "nothing_to_change": "Nothing to change",
    "address_required": "An email address is needed",
    "message_not_found": "Message not found",
    "relay_not_found": "No such reply address",
    "email_not_verified": "Email not verified",
    "bad_local": "Address name: Latin letters, digits, dot, hyphen and underscore, up to 40 characters; role names (noreply, postmaster…), the r- prefix and an ending like a reply address (_ and 12 characters) are taken",
    "bad_comment_type": "The comment must be text",
    "comment_too_long": "The comment is longer than 500 characters",
    "bad_sender_name_type": "The sender name must be text",
    "bad_sender_name": "Sender name: up to 100 characters, no @, quotes or angle brackets",
    "bad_forward": "The forwarding address must be an email address",
    "forward_loop": "Mail cannot be forwarded to an address of this same domain",
    "too_large": "Request too large",
    "bad_json_object": "A JSON object was expected",
    "bad_json": "Invalid JSON",
    "internal": "Internal error",
    "mail_disabled": "Mail is turned off here: nothing is received or sent",
    "limit_reached": "The limit of this installation is reached; delete something first",
    "bad_token": "Unauthenticated: a valid API key is needed",
    "bad_token_name": "Key name: up to 100 characters of text",
    "token_not_found": "API key not found",
    "bad_domain": "Unknown domain",
    "bad_format": "format must be random_words or custom",
    "bad_recipient": "The recipient must be an email address outside the alias domains",
    "bad_name": "Name: up to 100 characters, no @, quotes or angle brackets",
    "bad_subject": "Subject: text on one line, up to 300 characters",
    "bad_text": "The message must be text, up to 100,000 characters",
    "send_rejected": "SES did not send the message; while the account is in the SES sandbox the recipient has to be verified",
}


class ApiError(Exception):
    def __init__(self, status, code):
        super().__init__(ERRORS[code])
        self.status = status
        self.code = code
        self.message = ERRORS[code]


def handler(event, context):
    records = event.get("Records") if isinstance(event, dict) else None
    if records and "ses" in records[0]:
        return receive(records)
    if isinstance(event, dict) and "requestContext" in event:
        return api(event)
    return {"ok": True}


# Mail ---------------------------------------------------------------------

def receive(records):
    for record in records:
        mail = record["ses"].get("mail") or {}
        receipt = record["ses"].get("receipt") or {}
        raw = s3().get_object(Bucket=env("MAIL_BUCKET"), Key=env("MAIL_PREFIX") + mail["messageId"])["Body"].read()
        for recipient in receipt.get("recipients", []):
            try:
                route(recipient.lower(), raw, mail, receipt)
            except Exception:
                # One recipient failing must not stop the others; the message
                # stays in S3 for the retention period.
                logger.exception("recipient %s failed for message %s", recipient, mail.get("messageId"))
    return {"ok": True}


def route(recipient, raw, mail, receipt):
    local, _, domain = recipient.partition("@")
    if domain not in alias_domains():
        return "other domain"
    code = relay_code(local)
    if code:
        return reply(code, raw, mail, receipt)
    alias = get_alias(local)
    if not alias or not alias.get("active") or alias_domain(alias) != domain:
        logger.info("dropped: no active alias %s", local)
        return "unknown alias"
    return forward(alias, raw, mail, receipt)


def forward(alias, raw, mail, receipt):
    local = alias["sk"]
    if verdict(receipt, "virusVerdict") == "FAIL":
        logger.info("dropped: virus in a message for %s", local)
        return "virus"
    message = parse(raw)
    name, sender = first_address(message.get("Reply-To")) if message.get("Reply-To") else ("", "")
    from_name, from_address = first_address(message.get("From"))
    if not sender:
        name, sender = from_name, from_address
    if not sender:
        logger.info("dropped: no sender in a message for %s", local)
        return "no sender"
    code = reply_code(local, sender)
    table().put_item(Item={
        "pk": "REPLY",
        "sk": code,
        "alias": local,
        "sender": sender,
        "name": name,
        "updated_at": now_iso(),
    })
    subject = str(message.get("Subject", ""))
    spam = verdict(receipt, "spamVerdict") == "FAIL"
    drop_headers(message, ("From", "Reply-To") + DROPPED_HEADERS)
    domain = alias_domain(alias)
    relay = relay_address(sender, code, domain)
    relay_from = email.utils.formataddr((shown_sender(from_name, from_address or sender), relay))
    message["From"] = relay_from
    message["X-Hide-My-Email-Alias"] = f"{local}@{domain}"
    # A mark in a header, not "[SPAM]" in the subject: the subject itself would
    # make Gmail file the message as spam. A filter can use the header.
    if spam:
        message["X-Hide-My-Email-Spam"] = "yes"
    send(relay_from, [destination(alias)], signed(message, alias, relay.split("@")[0]))
    table().update_item(
        Key={"pk": "ALIAS", "sk": local},
        UpdateExpression="SET #forwarded = if_not_exists(#forwarded, :zero) + :one, #last_at = :now",
        ExpressionAttributeNames={"#forwarded": "forwarded", "#last_at": "last_at"},
        ExpressionAttributeValues={":zero": 0, ":one": 1, ":now": now_iso()},
    )
    log_message(mail, raw, {
        "direction": "in",
        "alias": local,
        "alias_domain": domain,
        "code": code,
        "relay": relay,
        "from_name": from_name,
        "from_address": from_address or sender,
        "to_name": "",
        "to_address": f"{local}@{domain}",
        "delivered_to": destination(alias),
        "subject": subject,
        "spam": spam,
    })
    return "forwarded"


def reply(code, raw, mail, receipt):
    message = parse(raw)
    item = table().get_item(Key={"pk": "REPLY", "sk": code}).get("Item")
    if not item:
        logger.info("dropped: unknown reply code %s", code)
        return "unknown code"
    alias = get_alias(item["alias"])
    owner = destination(alias) if alias else forward_to()
    if not from_owner(message, mail, receipt, owner):
        logger.info("dropped: reply to %s not from %s", code, owner)
        return "not the owner"
    domain = alias_domain(alias) if alias else domain_name()
    alias_address = f"{item['alias']}@{domain}"
    name = reply_name(alias, message)
    # Only the original sender gets the reply: copies would show the alias to
    # people who never wrote to it.
    drop_headers(message, ("From", "To", "Cc", "Bcc", "Reply-To") + DROPPED_HEADERS + REPLY_DROPPED_HEADERS)
    alias_from = email.utils.formataddr((name, alias_address))
    message["From"] = alias_from
    message["To"] = email.utils.formataddr((item.get("name") or "", item["sender"]))
    hide_owner(message, owner, alias_address)
    send(alias_from, [item["sender"]], signed(message, alias))
    log_message(mail, raw, {
        "direction": "out",
        "alias": item["alias"],
        "alias_domain": domain,
        "code": code,
        "relay": relay_address(item["sender"], code, domain),
        "from_name": name,
        "from_address": alias_address,
        "to_name": item.get("name") or "",
        "to_address": item["sender"],
        "delivered_to": item["sender"],
        "subject": str(message.get("Subject", "")),
        "spam": False,
    })
    return "replied"


# The log of forwarded messages and replies: a record to list and a copy of
# the original message to read, kept until the page deletes them. The message
# has gone out already, so a failure here is only logged.
def log_message(mail, raw, fields):
    return store_log(raw, fields, received=mail.get("messageId"))


# A received message is copied from MAIL_PREFIX; one written here (received is
# None) is stored as it was sent. Returns the id in the log, or None.
def store_log(raw, fields, received=None):
    at = now_iso()
    message_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(4)
    try:
        if received:
            s3().copy_object(
                Bucket=env("MAIL_BUCKET"),
                Key=env("MESSAGES_PREFIX") + message_id,
                CopySource={"Bucket": env("MAIL_BUCKET"), "Key": env("MAIL_PREFIX") + received},
            )
        else:
            s3().put_object(Bucket=env("MAIL_BUCKET"), Key=env("MESSAGES_PREFIX") + message_id, Body=raw)
        count = store_attachments(message_id, parse(raw))
        table().put_item(Item={"pk": "MSG", "sk": message_id, "at": at, "size": len(raw), "attachments": count, **fields})
        return message_id
    except Exception:
        logger.exception("message %s was not logged", received or message_id)
        return None


# The name shown with the alias in a reply: the alias's own sender name, or
# else the name the owner's mail client put in From.
def reply_name(alias, message):
    if alias and alias.get("sender_name"):
        return alias["sender_name"]
    return first_address(message.get("From"))[0].strip()


# The quoted text of a reply ("On …, Name <me@example.com> wrote") would show
# the personal address; it is replaced with the alias in every text part.
def hide_owner(message, owner, alias_address):
    pattern = re.compile(re.escape(owner), re.IGNORECASE)
    for part in message.walk():
        if part.get_content_maintype() != "text" or part.is_attachment():
            continue
        try:
            text = part.get_content()
        except (LookupError, ValueError):
            continue
        if pattern.search(text):
            part.set_content(pattern.sub(alias_address, text), subtype=part.get_content_subtype(), charset="utf-8")


# The sender's own message: From and the envelope are the expected address, and
# SES saw DMARC pass, or SPF pass for that same address when its domain has no
# DMARC record.
def from_owner(message, mail, receipt, owner):
    _, from_address = first_address(message.get("From"))
    owner = owner.lower()
    if from_address != owner or (mail.get("source") or "").lower() != owner:
        return False
    if verdict(receipt, "dmarcVerdict") == "PASS":
        return True
    return verdict(receipt, "dmarcVerdict") == "GRAY" and verdict(receipt, "spfVerdict") == "PASS"


# Aliases ------------------------------------------------------------------

def get_alias(local):
    return table().get_item(Key={"pk": "ALIAS", "sk": local}).get("Item")


# The domain of an alias: its own, or DOMAIN for aliases made before there
# were more.
def alias_domain(alias):
    return (alias.get("domain") or domain_name()).lower()


def alias_address(alias):
    return f"{alias['sk']}@{alias_domain(alias)}"


def destination(alias):
    return (alias.get("forward_to") or forward_to()).lower()


def create_alias(comment="", forward=None, local=None, sender_name="", domain=None):
    if limit_reached("ALIAS", "MAX_ALIASES"):
        raise ApiError(429, "limit_reached")
    for _ in range(1 if local else 20):
        name = local or f"{secrets.choice(ADJECTIVES)}-{secrets.choice(NOUNS)}-{secrets.randbelow(90) + 10}"
        now = now_iso()
        item = {"pk": "ALIAS", "sk": name, "comment": comment, "active": True, "created_at": now, "updated_at": now}
        if forward:
            item["forward_to"] = forward
        if domain and domain != domain_name():
            item["domain"] = domain
        if sender_name:
            item["sender_name"] = sender_name
        try:
            table().put_item(Item=item, ConditionExpression="attribute_not_exists(sk)")
            return item
        except Exception as exc:
            if error_code(exc) != "ConditionalCheckFailedException":
                raise
    if local:
        raise ApiError(409, "alias_exists")
    raise RuntimeError("no free alias after 20 tries")


# Field names go through ExpressionAttributeNames: "comment" is a reserved
# word of DynamoDB and fails as a bare name.
def change_alias(local, changes):
    sets = ["#updated_at = :now"]
    removes = []
    names = {"#updated_at": "updated_at"}
    values = {":now": now_iso()}
    for field in ("comment", "active", "pinned"):
        if field in changes:
            sets.append(f"#{field} = :{field}")
            names[f"#{field}"] = field
            values[f":{field}"] = changes[field]
    # An empty forwarding address or sender name means the default one.
    for field in ("forward_to", "sender_name"):
        if field not in changes:
            continue
        names[f"#{field}"] = field
        if changes[field]:
            sets.append(f"#{field} = :{field}")
            values[f":{field}"] = changes[field]
        else:
            removes.append(f"#{field}")
    expression = "SET " + ", ".join(sets) + (" REMOVE " + ", ".join(removes) if removes else "")
    try:
        return table().update_item(
            Key={"pk": "ALIAS", "sk": local},
            UpdateExpression=expression,
            ConditionExpression="attribute_exists(sk)",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        ).get("Attributes", {})
    except Exception as exc:
        if error_code(exc) == "ConditionalCheckFailedException":
            raise ApiError(404, "alias_not_found") from exc
        raise


def all_aliases():
    return sorted(query_all("ALIAS"), key=lambda item: item.get("created_at") or "", reverse=True)


# Every item of one partition, page after page.
def query_all(pk):
    from boto3.dynamodb.conditions import Key

    items = []
    kwargs = {"KeyConditionExpression": Key("pk").eq(pk)}
    while True:
        page = table().query(**kwargs)
        items.extend(page.get("Items", []))
        if not page.get("LastEvaluatedKey"):
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


# API ----------------------------------------------------------------------

def api(event):
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    parts = [unquote(part) for part in (event.get("rawPath") or "/").split("/") if part]
    if parts[:2] == ["api", "v1"]:
        return public_api(method, parts[2:], event)
    if parts[:2] == [".well-known", "openpgpkey"] and pgp_enabled():
        return web_key_directory(parts[2:], event)
    try:
        if parts[:1] != ["api"]:
            raise ApiError(404, "not_found")
        actor(event)
        result = api_route(method, parts[1:], event)
        if parts[1:] != ["session"]:
            attach_cookies(result)
    except ApiError as exc:
        result = response(exc.status, {"error": exc.message, "code": exc.code})
    except json.JSONDecodeError:
        result = response(400, {"error": ERRORS["bad_json"], "code": "bad_json"})
    except Exception:
        logger.exception("unhandled")
        result = response(500, {"error": ERRORS["internal"], "code": "internal"})
    logger.info("%s %s -> %s", method, event.get("rawPath"), result["statusCode"])
    return result


def api_route(method, parts, event):
    if parts == ["me"] and method == "GET":
        return response(200, {
            "email": actor(event),
            "domain": domain_name(),
            "domains": alias_domains(),
            "forward_to": forward_to(),
            "production": production_access(),
            "mail": mail_enabled(),
            "pgp": {"signing": signing_on()} if pgp_enabled() else None,
        })
    if parts == ["version"] and method == "GET":
        return response(200, version_info())
    if parts == ["settings", "pgp"] and method == "PUT":
        return response(200, set_signing(body_json(event).get("signing")))
    if parts == ["aliases"] and method == "GET":
        items = all_aliases()
        addresses = {forward_to()} | {destination(item) for item in items}
        return response(200, {
            "items": [public_alias(item) for item in items],
            "destinations": {address: destination_status(address) for address in sorted(addresses)},
            "production": production_access(),
        })
    if parts == ["aliases"] and method == "POST":
        payload = body_json(event)
        local = payload.get("local")
        if local:
            local = clean_local(local)
        item = create_alias(
            comment=clean_comment(payload.get("comment")),
            forward=clean_forward(payload.get("forward_to")),
            local=local,
            sender_name=clean_sender_name(payload.get("sender_name")),
            domain=clean_domain(payload.get("domain")),
        )
        return response(201, public_alias(item))
    if len(parts) == 2 and parts[0] == "aliases" and method == "PATCH":
        payload = body_json(event)
        changes = {}
        if "comment" in payload:
            changes["comment"] = clean_comment(payload["comment"])
        if "forward_to" in payload:
            changes["forward_to"] = clean_forward(payload["forward_to"])
        if "sender_name" in payload:
            changes["sender_name"] = clean_sender_name(payload["sender_name"])
        if "active" in payload:
            if not isinstance(payload["active"], bool):
                raise ApiError(400, "bad_active")
            changes["active"] = payload["active"]
        if not changes:
            raise ApiError(400, "nothing_to_change")
        return response(200, public_alias(change_alias(parts[1].lower(), changes)))
    if len(parts) == 2 and parts[0] == "aliases" and method == "DELETE":
        delete_alias(parts[1])
        return response(200, {"deleted": parts[1].lower()})
    if parts == ["tokens"] and method == "GET":
        items = sorted(query_all("TOKEN"), key=lambda item: item.get("created_at") or "", reverse=True)
        return response(200, {"items": [public_token(item) for item in items]})
    if parts == ["tokens"] and method == "POST":
        return response(201, create_token(clean_token_name(body_json(event).get("name")), actor(event)))
    if len(parts) == 2 and parts[0] == "tokens" and method == "DELETE":
        found = [item for item in query_all("TOKEN") if item.get("id") == parts[1]]
        if not found:
            raise ApiError(404, "token_not_found")
        table().delete_item(Key={"pk": "TOKEN", "sk": found[0]["sk"]})
        return response(200, {"deleted": parts[1]})
    if parts == ["destinations"] and method == "POST":
        if not mail_enabled():
            raise ApiError(400, "mail_disabled")
        address = clean_forward(body_json(event).get("address"))
        if not address:
            raise ApiError(400, "address_required")
        # SES sends a link to the address; asking again sends it again.
        ses_v1().verify_email_identity(EmailAddress=address)
        return response(200, {"address": address, "status": destination_status(address)})
    if len(parts) == 2 and parts[0] == "relays" and method == "GET":
        return response(200, find_relay(parts[1]))
    if parts == ["relays"] and method == "POST":
        payload = body_json(event)
        alias = existing_alias(str(payload.get("alias") or ""))
        address = clean_recipient(payload.get("address"))
        name = clean_name(payload.get("name"))
        if limit_reached("REPLY", "MAX_RELAYS"):
            raise ApiError(429, "limit_reached")
        return response(201, add_relay(alias, address, name))
    if len(parts) == 2 and parts[0] == "relays" and method == "DELETE":
        return response(200, delete_relay(parts[1]))
    if len(parts) == 3 and parts[0] == "aliases" and parts[2] == "key" and method == "GET":
        return response(200, public_signing_key(existing_alias(parts[1])))
    if len(parts) == 3 and parts[0] == "aliases" and parts[2] == "relays" and method == "GET":
        return response(200, {"items": alias_relays(existing_alias(parts[1]))})
    if parts == ["messages"] and method == "GET":
        params = event.get("queryStringParameters") or {}
        items, cursor = find_messages(params.get("alias", ""), params.get("q", ""), params.get("cursor", ""), MESSAGE_PAGE)
        return response(200, {"items": [public_message(item) for item in items], "cursor": cursor})
    if parts == ["messages"] and method == "POST":
        return response(201, send_new(body_json(event, limit=MESSAGE_BODY_LIMIT)))
    if parts == ["messages"] and method == "DELETE":
        params = event.get("queryStringParameters") or {}
        items, _ = find_messages(params.get("alias", ""), params.get("q", ""))
        delete_messages(items)
        return response(200, {"deleted": len(items)})
    if len(parts) == 2 and parts[0] == "messages" and method == "GET":
        return response(200, read_message(parts[1]))
    if len(parts) == 2 and parts[0] == "messages" and method == "DELETE":
        item = table().get_item(Key={"pk": "MSG", "sk": parts[1]}).get("Item")
        if not item:
            raise ApiError(404, "message_not_found")
        delete_messages([item])
        return response(200, {"deleted": 1})
    # Sign-out: the attachment cookie goes too.
    if parts == ["session"] and method == "DELETE":
        return {**response(200, {"ok": True}), "cookies": attachment_cookies(expired=True)}
    raise ApiError(404, "not_found")


def delete_alias(local):
    try:
        table().delete_item(Key={"pk": "ALIAS", "sk": local.lower()}, ConditionExpression="attribute_exists(sk)")
    except Exception as exc:
        if error_code(exc) == "ConditionalCheckFailedException":
            raise ApiError(404, "alias_not_found") from exc
        raise


# API keys ---------------------------------------------------------------------
#
# A key is hme and 48 random letters and digits; only its SHA-256 is kept, so
# the table cannot give a key away. The page shows a new key once.

def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_token(name, created_by):
    if limit_reached("TOKEN", "MAX_TOKENS"):
        raise ApiError(429, "limit_reached")
    token = TOKEN_PREFIX + "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(48))
    digest = token_hash(token)
    item = {"pk": "TOKEN", "sk": digest, "id": digest[:12], "name": name, "created_by": created_by, "created_at": now_iso()}
    table().put_item(Item=item)
    return {**public_token(item), "token": token}


def public_token(item):
    return {
        "id": item["id"],
        "name": item.get("name") or "",
        "created_by": item.get("created_by") or "",
        "created_at": item.get("created_at") or "",
        "last_used_at": item.get("last_used_at") or "",
    }


def clean_token_name(value):
    if value in (None, ""):
        return "API"
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 100:
        raise ApiError(400, "bad_token_name")
    return " ".join(value.split())


def token_owner(event):
    header = (event.get("headers") or {}).get("authorization") or ""
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token.startswith(TOKEN_PREFIX):
        raise ApiError(401, "bad_token")
    item = table().get_item(Key={"pk": "TOKEN", "sk": token_hash(token)}).get("Item")
    if not item:
        raise ApiError(401, "bad_token")
    try:
        table().update_item(
            Key={"pk": "TOKEN", "sk": item["sk"]},
            UpdateExpression="SET #last_used_at = :now",
            ExpressionAttributeNames={"#last_used_at": "last_used_at"},
            ExpressionAttributeValues={":now": now_iso()},
        )
    except Exception:
        logger.exception("last use of key %s was not saved", item.get("id"))
    return item


# The addy.io API ----------------------------------------------------------------
#
# What Bitwarden's generator and the addy.io browser extension call, in the
# shapes they read. Bitwarden only POSTs /aliases with {"domain",
# "description"} and reads data.email. The extension signs in with
# /domain-options, loads /recipients and /labels, lists /aliases with
# filter[...], sort and page[...], and creates, edits, turns on and off, pins
# and deletes aliases. The addy.io apps for Android and iOS sign in with
# /account-details and /api-token-details, check /app-version against the
# server version they need, and open lists this relay does not have
# (usernames, domains, rules, failed deliveries, blocklist, notifications),
# which come back empty. The iOS app decodes strictly: fields it declares
# as strings or booleans must be there and must not be null, times are
# "YYYY-MM-DD HH:MM:SS" and a page has meta.links and meta.path. There are no labels here: the list is empty and label
# changes are accepted and dropped. Every random format (random_words,
# random_characters, uuid) gives the usual random name. Errors are
# {"message": ...} as in addy.io; validation errors also carry "errors".

def public_api(method, parts, event):
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": dict(CORS_HEADERS), "body": ""}
    try:
        key = token_owner(event)
        result = public_route(method, parts, event, key)
        logger.info("key %s: %s %s", key["id"], method, "/".join(parts))
    except ApiError as exc:
        payload = {"message": exc.message, "code": exc.code}
        if exc.status == 422:
            payload["errors"] = {exc.code: [exc.message]}
        result = response(exc.status, payload)
    except json.JSONDecodeError:
        result = response(400, {"message": ERRORS["bad_json"], "code": "bad_json"})
    except Exception:
        logger.exception("unhandled")
        result = response(500, {"message": ERRORS["internal"], "code": "internal"})
    result["headers"] = {**result["headers"], **CORS_HEADERS}
    logger.info("%s /api/v1/%s -> %s", method, "/".join(parts), result["statusCode"])
    return result


def no_content():
    return {"statusCode": 204, "headers": {"cache-control": "no-store"}, "body": ""}


def public_route(method, parts, event, key=None):
    params = event.get("queryStringParameters") or {}
    if parts == ["account-details"] and method == "GET":
        return response(200, {"data": addy_account(key or {})})
    if parts == ["api-token-details"] and method == "GET":
        return response(200, {"name": (key or {}).get("name") or "", "created_at": addy_time((key or {}).get("created_at")) or "", "expires_at": None})
    if parts == ["app-version"] and method == "GET":
        major, minor, patch = (int(part) for part in ADDY_VERSION.split("."))
        return response(200, {"version": ADDY_VERSION, "major": major, "minor": minor, "patch": patch})
    if parts in (["usernames"], ["domains"], ["rules"], ["failed-deliveries"], ["blocklist"], ["account-notifications"]) and method == "GET":
        return response(200, {"data": []})
    if parts == ["domain-options"] and method == "GET":
        return response(200, {
            "data": alias_domains(),
            "sharedDomains": [],
            "defaultAliasDomain": domain_name(),
            "defaultAliasFormat": "random_words",
        })
    if parts == ["recipients"] and method == "GET":
        addresses = sorted({forward_to()} | {destination(item) for item in all_aliases()})
        items = all_aliases()
        since = min((item.get("created_at") or "" for item in items), default="")
        addresses = sorted({forward_to()} | {destination(item) for item in items})
        return response(200, {"data": [addy_recipient(address, since) for address in addresses]})
    if len(parts) == 2 and parts[0] == "recipients" and method == "GET":
        items = all_aliases()
        address = parts[1].strip().lower()
        if address not in {forward_to()} | {destination(item) for item in items}:
            raise ApiError(404, "not_found")
        return response(200, {"data": addy_recipient(address, min((item.get("created_at") or "" for item in items), default=""))})
    if parts == ["labels"] and method == "GET":
        return response(200, {"data": []})
    if parts == ["aliases"] and method == "GET":
        return response(200, addy_list(params))
    if parts == ["aliases"] and method == "POST":
        return response(201, {"data": addy_alias(addy_create(body_json(event)))})
    if len(parts) == 2 and parts[0] == "aliases" and method == "GET":
        return response(200, {"data": addy_alias(existing_alias(parts[1]))})
    if len(parts) == 2 and parts[0] == "aliases" and method == "PATCH":
        description = body_json(event).get("description")
        comment = clean_comment(description[:500] if isinstance(description, str) else description)
        return response(200, {"data": addy_alias(change_alias(parts[1].lower(), {"comment": comment}))})
    if len(parts) == 2 and parts[0] == "aliases" and method == "DELETE":
        delete_alias(parts[1])
        return no_content()
    if parts == ["active-aliases"] and method == "POST":
        return response(200, {"data": addy_alias(change_alias(str(body_json(event).get("id") or "").lower(), {"active": True}))})
    if len(parts) == 2 and parts[0] == "active-aliases" and method == "DELETE":
        change_alias(parts[1].lower(), {"active": False})
        return no_content()
    if parts == ["pinned-aliases"] and method == "POST":
        return response(200, {"data": addy_alias(change_alias(str(body_json(event).get("id") or "").lower(), {"pinned": True}))})
    if len(parts) == 2 and parts[0] == "pinned-aliases" and method == "DELETE":
        change_alias(parts[1].lower(), {"pinned": False})
        return no_content()
    if parts == ["alias-labels"] and method == "POST":
        return response(200, {"data": addy_alias(existing_alias(str(body_json(event).get("alias_id") or "")))})
    raise ApiError(404, "not_found")


def existing_alias(local):
    item = get_alias(local.lower())
    if not item:
        raise ApiError(404, "alias_not_found")
    return item


def addy_create(payload):
    domain = clean_domain(payload.get("domain"), status=422)
    description = payload.get("description")
    comment = clean_comment(description[:500] if isinstance(description, str) else description)
    alias_format = payload.get("format") or "random_words"
    if alias_format not in ("random_words", "random_characters", "uuid", "custom"):
        raise ApiError(422, "bad_format")
    local = clean_local(payload.get("local_part") or "") if alias_format == "custom" else None
    # One recipient of the list becomes the forwarding address of the alias.
    forward = None
    recipient_ids = payload.get("recipient_ids") or []
    if isinstance(recipient_ids, list) and len(recipient_ids) == 1:
        forward = clean_forward(recipient_ids[0]) or None
        if forward == forward_to():
            forward = None
    return create_alias(comment=comment, forward=forward, local=local, domain=domain)


# The alias list as addy.io pages it: filter[deleted|active|pinned|search],
# sort (a field, "-" for descending) and page[number|size]. Deleted aliases
# are gone here, so filter[deleted]=only finds none.
def addy_list(params):
    items = [addy_alias(item) for item in all_aliases()]
    if params.get("filter[deleted]") == "only":
        items = []
    for name in ("active", "pinned"):
        wanted = params.get(f"filter[{name}]")
        if wanted in ("true", "false"):
            items = [item for item in items if item[name] == (wanted == "true")]
    search = (params.get("filter[search]") or "").strip().lower()
    if search:
        items = [item for item in items if search in item["email"] or search in (item["description"] or "").lower()]
    order = params.get("sort") or "-created_at"
    field = order.lstrip("-")
    if items and field in items[0]:
        items.sort(key=lambda item: (item[field] is None, item[field] if item[field] is not None else ""), reverse=order.startswith("-"))
    total = len(items)
    size = as_int(params.get("page[size]"), total or 1)
    number = max(1, as_int(params.get("page[number]"), 1))
    last = max(1, -(-total // size))
    page = items[(number - 1) * size:number * size]
    # Relative: the demo has no domain of its own, and clients only look at
    # whether "next" is there.
    base = "/api/v1/aliases"
    return {
        "data": page,
        "links": {
            "first": f"{base}?page[number]=1",
            "last": f"{base}?page[number]={last}",
            "prev": f"{base}?page[number]={number - 1}" if number > 1 else None,
            "next": f"{base}?page[number]={number + 1}" if number < last else None,
        },
        "meta": {"current_page": number, "last_page": last, "per_page": size, "total": total,
                 "path": base, "links": [],
                 "from": (number - 1) * size + 1 if page else None, "to": (number - 1) * size + len(page) if page else None},
    }


def as_int(value, default):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


# The account as the addy.io apps show it: one self-hosted account without
# limits (0 is "unlimited" in addy.io), its domains and the counts of its
# aliases.
def addy_account(key):
    items = all_aliases()
    active = sum(1 for item in items if item.get("active"))
    recipients = {forward_to()} | {destination(item) for item in items}
    return {
        "id": key.get("id") or "",
        "username": forward_to().split("@")[0],
        "from_name": None,
        "email_subject": None,
        "banner_location": "off",
        "spam_warning_behaviour": "off",
        "wkd_auto_encrypt": 0,
        "bandwidth": 0,
        "username_count": 0,
        "username_limit": 0,
        "default_username_id": "",
        "default_recipient_id": forward_to(),
        "default_alias_domain": domain_name(),
        "default_alias_format": "random_words",
        "alias_separator": ".",
        "subscription": None,
        "subscription_type": None,
        "subscription_ends_at": None,
        "family_plan_role": None,
        "bandwidth_limit": 0,
        "recipient_count": len(recipients),
        "recipient_limit": 0,
        "active_domain_count": len(alias_domains()),
        "active_domain_limit": 0,
        "active_shared_domain_alias_count": 0,
        "active_shared_domain_alias_limit": 0,
        "active_rule_count": 0,
        "active_rule_limit": 0,
        "total_emails_forwarded": sum(int(item.get("forwarded") or 0) for item in items),
        "total_emails_blocked": 0,
        "total_emails_replied": 0,
        "total_emails_sent": 0,
        "total_aliases": len(items),
        "total_active_aliases": active,
        "total_inactive_aliases": len(items) - active,
        "total_pinned_aliases": sum(1 for item in items if item.get("pinned")),
        "total_deleted_aliases": 0,
        "created_at": addy_time(key.get("created_at")) or "",
        "updated_at": addy_time(key.get("last_used_at") or key.get("created_at")) or "",
    }


# "2026-10-12T09:04:03Z" as addy.io writes times: "2026-10-12 09:04:03".
def addy_time(value):
    return (value or "")[:19].replace("T", " ") or None


def addy_alias(item):
    return {
        "id": item["sk"],
        "user_id": "",
        "local_part": item["sk"],
        "extension": None,
        "domain": alias_domain(item),
        "email": alias_address(item),
        "active": bool(item.get("active")),
        "pinned": bool(item.get("pinned")),
        "description": item.get("comment") or None,
        "from_name": item.get("sender_name") or None,
        "attached_recipients_only": False,
        "recipients": [addy_recipient(destination(item), item.get("created_at"))],
        "labels": [],
        "emails_forwarded": int(item.get("forwarded") or 0),
        "emails_blocked": 0,
        "emails_replied": 0,
        "emails_sent": 0,
        "last_forwarded": addy_time(item.get("last_at")),
        "last_blocked": None,
        "last_replied": None,
        "last_sent": None,
        "created_at": addy_time(item.get("created_at")) or "",
        "updated_at": addy_time(item.get("updated_at") or item.get("created_at")) or "",
        "deleted_at": None,
    }


# A forwarding address as an addy.io recipient: verified (SES sends to it),
# no encryption. Its times are those of the oldest alias that uses it, or of
# the alias asked about.
def addy_recipient(address, since=None):
    when = addy_time(since) or ""
    return {
        "id": address,
        "user_id": "",
        "email": address,
        "description": None,
        "can_reply_send": True,
        "should_encrypt": False,
        "inline_encryption": False,
        "protected_headers": False,
        "remove_pgp_keys": False,
        "remove_pgp_signatures": False,
        "fingerprint": None,
        "active": True,
        "email_verified_at": when or None,
        "aliases_count": None,
        "created_at": when,
        "updated_at": when,
    }


# The conversation behind a relay address: whose messages it brings and
# through which alias.
def find_relay(address):
    code = relay_code(address)
    item = table().get_item(Key={"pk": "REPLY", "sk": code}).get("Item") if code else None
    if not item:
        raise ApiError(404, "relay_not_found")
    alias = get_alias(item["alias"])
    domain = alias_domain(alias) if alias else domain_name()
    return {
        "code": code,
        "relay": relay_address(item["sender"], code, domain),
        "alias": item["alias"],
        "address": f"{item['alias']}@{domain}",
        "sender": item["sender"],
        "name": item.get("name") or "",
    }


# OpenPGP signatures --------------------------------------------------------

# The key of an alias, or of one of its relay addresses (relay: the local
# part), which signs the mail forwarded from that address. Its seed comes from
# the secret and the local part with the time the key of the alias was made;
# that time is set once, on first use, so the keys and their fingerprints stay
# the same for the life of the alias. Aliases never end like a relay address,
# so no two addresses share a key.
def alias_signing_key(alias, relay=None):
    created = alias.get("pgp_created")
    if not created:
        created = int(datetime.now(timezone.utc).timestamp())
        try:
            table().update_item(
                Key={"pk": "ALIAS", "sk": alias["sk"]},
                UpdateExpression="SET #created = :created",
                ConditionExpression="attribute_exists(sk) AND attribute_not_exists(#created)",
                ExpressionAttributeNames={"#created": "pgp_created"},
                ExpressionAttributeValues={":created": created},
            )
        except Exception as exc:
            if error_code(exc) != "ConditionalCheckFailedException":
                raise
            # Made a moment ago by another call; that one counts.
            created = (get_alias(alias["sk"]) or {}).get("pgp_created") or created
        alias["pgp_created"] = created
    local = relay or alias["sk"]
    seed = hmac.new(pgp_secret(), f"{local}\n{int(created)}".encode(), hashlib.sha256).digest()
    return pgp.SigningKey(seed, int(created), f"{local}@{alias_domain(alias)}")


def pgp_secret():
    global _pgp_secret
    if _pgp_secret is None:
        value = ssm().get_parameter(Name=env("PGP_SECRET_PARAMETER"), WithDecryption=True)["Parameter"]["Value"]
        _pgp_secret = hashlib.sha256(value.encode()).digest()
    return _pgp_secret


# Two switches. PGP=false (the Terraform variable pgp_enabled) is no PGP at
# all: no signatures, no key on the page, no Web Key Directory. The switch on
# the page (SETTING pgp, "signing") stops the signatures and hides the keys,
# while the directory keeps serving them for the mail already signed; the keys
# stay the same either way.
def pgp_enabled():
    return os.environ.get("PGP", "true").lower() != "false"


def signing_on():
    if not pgp_enabled():
        return False
    item = table().get_item(Key={"pk": "SETTING", "sk": "pgp"}).get("Item") or {}
    return item.get("signing", True) is not False


def set_signing(signing):
    if not pgp_enabled():
        raise ApiError(404, "not_found")
    if not isinstance(signing, bool):
        raise ApiError(400, "bad_signing")
    table().put_item(Item={"pk": "SETTING", "sk": "pgp", "signing": signing, "updated_at": now_iso()})
    return {"signing": signing}


def public_signing_key(alias):
    if not signing_on():
        raise ApiError(404, "not_found")
    key = alias_signing_key(alias)
    return {
        "fingerprint": key.fingerprint.hex().upper(),
        "user_id": key.user_id,
        "created_at": datetime.fromtimestamp(key.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "key": key.armored_public_key(),
        # Relative in the demo: its page is not at the domain of the aliases.
        "wkd": (f"https://{alias_domain(alias)}" if mail_enabled() else "") + f"/.well-known/openpgpkey/hu/{pgp.wkd_hash(alias['sk'])}?l={quote(alias['sk'])}",
    }


# The message signed by the address it comes from (the alias, or its relay
# address for forwarded mail), as bytes to send as they are; the message
# itself, unsigned, if signing fails: the mail matters more than its signature.
def signed(message, alias, relay=None):
    if not alias:
        return message
    try:
        if not signing_on():
            return message
        return signed_message(message, alias_signing_key(alias, relay))
    except Exception:
        logger.exception("message of %s not signed", relay or alias.get("sk"))
        return message


# PGP/MIME (RFC 3156): the content of the message (its Content-* headers and
# body) is the signed part, the signature the second part of
# multipart/signed. Mail servers may re-encode 8-bit text, strip trailing
# spaces or rewrap long lines, any of which would break the signature, so
# every text part is quoted-printable and every other part base64 first.
def signed_message(message, key):
    raw = message.as_bytes(policy=email.policy.SMTP)
    header_block = raw.split(b"\r\n\r\n", 1)[0]
    content = parse(raw)
    for name in {name for name in content.keys() if not name.lower().startswith("content-")}:
        del content[name]
    if "Content-Type" not in content:
        content["Content-Type"] = "text/plain; charset=us-ascii"
    transport_safe(content)
    part = content.as_bytes(policy=email.policy.SMTP)
    signature = key.sign(part).encode()
    boundary = "hme-signed-" + secrets.token_hex(12)
    headers = [field for field in header_fields(header_block) if not field.lower().startswith((b"content-", b"mime-version:"))]
    return b"".join([
        *[field + b"\r\n" for field in headers],
        b"MIME-Version: 1.0\r\n",
        b'Content-Type: multipart/signed; micalg=pgp-sha256;\r\n protocol="application/pgp-signature";\r\n boundary="' + boundary.encode() + b'"\r\n',
        b"\r\n",
        b"This is an OpenPGP/MIME signed message (RFC 4880 and 3156)\r\n",
        b"--" + boundary.encode() + b"\r\n",
        part,
        b"\r\n--" + boundary.encode() + b"\r\n",
        b'Content-Type: application/pgp-signature; name="signature.asc"\r\n',
        b"Content-Description: OpenPGP digital signature\r\n",
        b'Content-Disposition: attachment; filename="signature.asc"\r\n',
        b"\r\n",
        signature,
        b"\r\n--" + boundary.encode() + b"--\r\n",
    ])


# The fields of a header block, each with its folded lines.
def header_fields(block):
    fields = []
    for line in block.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and fields:
            fields[-1] += b"\r\n" + line
        elif line:
            fields.append(line)
    return fields


# Signed or encrypted parts of a forwarded message stay as they are: new
# encodings would break the signatures of their senders.
def transport_safe(message):
    if message.get_content_type() in ("multipart/signed", "multipart/encrypted"):
        return
    if message.is_multipart():
        for part in message.get_payload():
            transport_safe(part)
        return
    if message.get_content_maintype() == "message":
        return
    if (message.get("Content-Transfer-Encoding") or "").lower() in ("base64", "quoted-printable"):
        return
    data = message.get_payload(decode=True) or b""
    del message["Content-Transfer-Encoding"]
    if message.get_content_maintype() == "text":
        encoded = quopri.encodestring(data.replace(b"\r\n", b"\n")).decode("ascii")
        # "From " at the start of a line may become ">From " in a mailbox.
        encoded = re.sub(r"(?m)^From ", "=46rom ", encoded)
        message.set_payload(encoded)
        message["Content-Transfer-Encoding"] = "quoted-printable"
    else:
        message.set_payload(base64.encodebytes(data).decode("ascii"))
        message["Content-Transfer-Encoding"] = "base64"


# The Web Key Directory of the domain the page was asked on (CloudFront names
# it in X-Hide-My-Email-Site): the policy and the key of each of its aliases
# and relay addresses, found by the hash of the local part (direct method).
def web_key_directory(parts, event):
    headers = {name.lower(): value for name, value in (event.get("headers") or {}).items()}
    domain = (headers.get("x-hide-my-email-site") or domain_name()).lower()
    plain = {"Access-Control-Allow-Origin": "*", "Cache-Control": "max-age=3600"}
    if parts == ["policy"]:
        return {"statusCode": 200, "headers": {**plain, "Content-Type": "text/plain"}, "body": ""}
    if len(parts) == 2 and parts[0] == "hu":
        local = ((event.get("queryStringParameters") or {}).get("l") or "").lower()
        for alias, relay in directory_candidates(local):
            if alias and alias_domain(alias) == domain and pgp.wkd_hash(relay or alias["sk"]) == parts[1]:
                return {
                    "statusCode": 200,
                    "headers": {**plain, "Content-Type": "application/octet-stream"},
                    "body": base64.b64encode(alias_signing_key(alias, relay).public_key()).decode(),
                    "isBase64Encoded": True,
                }
    return {"statusCode": 404, "headers": {**plain, "Content-Type": "text/plain"}, "body": "not found"}


# The addresses a key may be asked for, as (alias, relay local part or None):
# the one named by ?l=, or else every alias and relay address.
def directory_candidates(local):
    if local:
        alias = get_alias(local)
        if alias:
            return [(alias, None)]
        code = relay_code(local)
        item = table().get_item(Key={"pk": "REPLY", "sk": code}).get("Item") if code else None
        if item and relay_address(item["sender"], code).split("@")[0] == local:
            return [(get_alias(item["alias"]), local)]
        return []
    aliases = {alias["sk"]: alias for alias in all_aliases()}
    relays = [(aliases.get(item["alias"]), relay_address(item["sender"], item["sk"]).split("@")[0]) for item in query_all("REPLY")]
    return [(alias, None) for alias in aliases.values()] + relays


# The relay address of a correspondent and what the page shows of it.
def public_relay(item, alias):
    domain = alias_domain(alias) if alias else domain_name()
    return {
        "code": item["sk"],
        "relay": relay_address(item["sender"], item["sk"], domain),
        "alias": item["alias"],
        "address": f"{item['alias']}@{domain}",
        "sender": item["sender"],
        "name": item.get("name") or "",
        "updated_at": item.get("updated_at") or "",
    }


# A correspondent of an alias without a message from them: the same record a
# forwarded message makes, so mail to the relay address from the forwarding
# address goes to them. Adding one that is there already keeps its name
# unless a new one is given.
def add_relay(alias, address, name=""):
    local = alias["sk"]
    code = reply_code(local, address)
    found = table().get_item(Key={"pk": "REPLY", "sk": code}).get("Item") or {}
    item = {
        "pk": "REPLY",
        "sk": code,
        "alias": local,
        "sender": address,
        "name": name or found.get("name") or "",
        "updated_at": now_iso(),
    }
    table().put_item(Item=item)
    return public_relay(item, alias)


def delete_relay(address):
    code = relay_code(address)
    try:
        table().delete_item(Key={"pk": "REPLY", "sk": code or ""}, ConditionExpression="attribute_exists(sk)")
    except Exception as exc:
        if error_code(exc) == "ConditionalCheckFailedException":
            raise ApiError(404, "relay_not_found") from exc
        raise
    return {"deleted": code}


# Everyone with a relay address for the alias: who wrote to it and whom the
# page added, by address.
def alias_relays(alias):
    items = [item for item in query_all("REPLY") if item.get("alias") == alias["sk"]]
    return [public_relay(item, alias) for item in sorted(items, key=lambda item: item["sender"])]


# A new plain text message from an alias, written on the page. The recipient
# becomes a correspondent of the alias, so that mail from the forwarding
# address to the relay address carries the conversation on.
def send_new(payload):
    if not mail_enabled():
        raise ApiError(400, "mail_disabled")
    alias = existing_alias(str(payload.get("alias") or ""))
    to = clean_recipient(payload.get("to"))
    subject = clean_subject(payload.get("subject"))
    text = payload.get("text")
    if not isinstance(text, str) or len(text) > TEXT_LIMIT:
        raise ApiError(400, "bad_text")
    relay = add_relay(alias, to)
    domain = alias_domain(alias)
    address = alias_address(alias)
    name = alias.get("sender_name") or ""
    message = email.message.EmailMessage(policy=email.policy.SMTP)
    alias_from = email.utils.formataddr((name, address))
    message["From"] = alias_from
    message["To"] = email.utils.formataddr((relay["name"], to))
    message["Subject"] = subject
    message["Date"] = email.utils.formatdate(usegmt=True)
    message["Message-ID"] = email.utils.make_msgid(domain=domain)
    message.set_content(text)
    outgoing = signed(message, alias)
    try:
        send(alias_from, [to], outgoing)
    except Exception as exc:
        if error_code(exc) in ("MessageRejected", "AccountSendingPausedException", "MailFromDomainNotVerifiedException"):
            raise ApiError(400, "send_rejected") from exc
        raise
    message_id = store_log(outgoing if isinstance(outgoing, bytes) else outgoing.as_bytes(policy=email.policy.SMTP), {
        "direction": "out",
        "alias": alias["sk"],
        "alias_domain": domain,
        "code": relay["code"],
        "relay": relay["relay"],
        "from_name": name,
        "from_address": address,
        "to_name": relay["name"],
        "to_address": to,
        "delivered_to": to,
        "subject": subject,
        "spam": False,
    })
    return {"id": message_id, "to": to, "relay": relay["relay"]}


# Messages newest first, those of one alias and those that mention the query
# (a relay address in either form counts by its code). Returns up to limit
# items and the id to continue after, or "" at the end.
def find_messages(alias="", query="", cursor="", limit=None):
    from boto3.dynamodb.conditions import Key

    alias = alias.strip().lower().split("@")[0]
    query = query.strip().lower()
    code = relay_code(query)
    kwargs = {"KeyConditionExpression": Key("pk").eq("MSG"), "ScanIndexForward": False}
    if cursor:
        kwargs["ExclusiveStartKey"] = {"pk": "MSG", "sk": cursor}
    items = []
    while True:
        page = table().query(**kwargs)
        for item in page.get("Items", []):
            if alias and item.get("alias") != alias:
                continue
            if query and not (code and item.get("code") == code or query in message_text(item)):
                continue
            items.append(item)
            if limit and len(items) == limit:
                return items, item["sk"]
        if not page.get("LastEvaluatedKey"):
            return items, ""
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def message_text(item):
    fields = ("from_name", "from_address", "to_name", "to_address", "delivered_to", "subject", "relay")
    return "\n".join([str(item.get(field) or "") for field in fields] + [logged_alias_address(item)]).lower()


# Deletes log records with the copy of each message and its attachments.
def delete_messages(items):
    with table().batch_writer() as batch:
        for item in items:
            batch.delete_item(Key={"pk": "MSG", "sk": item["sk"]})
    keys = []
    for item in items:
        keys.append(env("MESSAGES_PREFIX") + item["sk"])
        keys.extend(attachment_key(item["sk"], index) for index in range(int(item.get("attachments") or 0)))
    for start in range(0, len(keys), 1000):
        s3().delete_objects(Bucket=env("MAIL_BUCKET"), Delete={
            "Objects": [{"Key": key} for key in keys[start:start + 1000]],
            "Quiet": True,
        })


def public_message(item):
    return {
        "id": item["sk"],
        "direction": item.get("direction") or "in",
        "alias": logged_alias_address(item),
        "relay": item.get("relay") or "",
        "from_name": item.get("from_name") or "",
        "from_address": item.get("from_address") or "",
        "to_name": item.get("to_name") or "",
        "to_address": item.get("to_address") or "",
        "delivered_to": item.get("delivered_to") or "",
        "subject": item.get("subject") or "",
        "at": item.get("at") or "",
        "size": int(item.get("size") or 0),
        "spam": bool(item.get("spam")),
    }


# One logged message with its text: the plain part, or the HTML part as text.
# HTML is not handed to the page: it could run scripts and load trackers.
def read_message(message_id):
    item = table().get_item(Key={"pk": "MSG", "sk": message_id}).get("Item")
    if not item:
        raise ApiError(404, "message_not_found")
    result = public_message(item)
    try:
        raw = s3().get_object(Bucket=env("MAIL_BUCKET"), Key=env("MESSAGES_PREFIX") + message_id)["Body"].read()
    except Exception as exc:
        if error_code(exc) != "NoSuchKey":
            raise
        return {**result, "headers": {}, "text": "", "attachments": [], "missing": True}
    message = parse(raw)
    # Messages logged before attachments were stored apart get them now.
    if "attachments" not in item:
        count = store_attachments(message_id, message)
        table().update_item(
            Key={"pk": "MSG", "sk": message_id},
            UpdateExpression="SET #attachments = :count",
            ExpressionAttributeNames={"#attachments": "attachments"},
            ExpressionAttributeValues={":count": count},
        )
    headers = {name: str(message.get(name)) for name in ("From", "To", "Cc", "Reply-To", "Date", "Subject") if message.get(name)}
    body = message.get_body(("plain", "html"))
    text = ""
    if body is not None:
        try:
            text = body.get_content()
        except (LookupError, ValueError):
            text = ""
        if body.get_content_subtype() == "html":
            text = html_text(text)
    files = [
        {
            "index": index,
            "name": part.get_filename() or "",
            "type": part.get_content_type(),
            "size": len(part.get_payload(decode=True) or b""),
            "url": "/" + attachment_key(message_id, index),
        }
        for index, part in enumerate(attachments(message))
    ]
    return {**result, "headers": headers, "text": text[:200_000], "attachments": files, "missing": False}


def attachments(message):
    return [part for part in message.walk() if part.is_attachment()]


# Each attachment as an object of its own, which CloudFront serves at the same
# path. The type is octet-stream and the disposition "attachment": the browser
# saves the file and never opens it as a page of this site. Returns the count.
def store_attachments(message_id, message):
    parts = attachments(message)
    for index, part in enumerate(parts):
        s3().put_object(
            Bucket=env("MAIL_BUCKET"),
            Key=attachment_key(message_id, index),
            Body=part.get_payload(decode=True) or b"",
            ContentType="application/octet-stream",
            ContentDisposition=content_disposition(part.get_filename() or f"attachment-{index + 1}"),
        )
    return len(parts)


def attachment_key(message_id, index):
    return f"{env('ATTACHMENTS_PREFIX')}{message_id}/{index}"


# A file name for Content-Disposition: an ASCII fallback for old clients and
# the real name in UTF-8 (RFC 6266).
def content_disposition(name):
    name = re.sub(r"[\r\n\\/]", "_", name)
    fallback = re.sub(r'[^A-Za-z0-9._ -]', "_", name) or "attachment"
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(name, safe='')}"


# The signed cookie of CloudFront ---------------------------------------------
#
# /attachments/* on CloudFront trusts one key group: a request passes only with
# cookies signed by its private key. The API hands them out with every
# successful answer, that is only after API Gateway has checked the Cognito
# token; they last COOKIE_SECONDS and the browser sends them to /attachments
# only.

def attach_cookies(result):
    if not 200 <= result["statusCode"] < 300:
        return
    try:
        result["cookies"] = attachment_cookies()
    except Exception:
        logger.exception("attachment cookie was not issued")


def attachment_cookies(expired=False):
    attributes = f"Path=/{env('ATTACHMENTS_PREFIX').rstrip('/')}; Secure; HttpOnly; SameSite=Strict; Max-Age="
    if expired:
        return [f"{name}=; {attributes}0" for name in ("CloudFront-Policy", "CloudFront-Signature", "CloudFront-Key-Pair-Id")]
    import time

    policy = json.dumps({
        "Statement": [{
            # Any host: the page has a distribution per domain, all of them
            # trust only this key, and the browser keeps the cookie for the
            # host that set it.
            "Resource": f"https://*/{env('ATTACHMENTS_PREFIX')}*",
            "Condition": {"DateLessThan": {"AWS:EpochTime": int(time.time()) + COOKIE_SECONDS}},
        }]
    }, separators=(",", ":")).encode()
    signature = rsa_sha1_sign(policy, signing_key())
    return [
        f"CloudFront-Policy={cloudfront_b64(policy)}; {attributes}{COOKIE_SECONDS}",
        f"CloudFront-Signature={cloudfront_b64(signature)}; {attributes}{COOKIE_SECONDS}",
        f"CloudFront-Key-Pair-Id={env('CLOUDFRONT_KEY_PAIR_ID')}; {attributes}{COOKIE_SECONDS}",
    ]


def cloudfront_b64(data):
    return base64.b64encode(data).decode("ascii").replace("+", "-").replace("=", "_").replace("/", "~")


# The private key lives in SSM Parameter Store (SecureString), read once per
# container.
def signing_key():
    global _signing_key
    if _signing_key is None:
        parameter = ssm().get_parameter(Name=env("SIGNING_KEY_PARAMETER"), WithDecryption=True)
        _signing_key = load_rsa_private_key(parameter["Parameter"]["Value"])
    return _signing_key


# CloudFront wants RSASSA-PKCS1-v1_5 with SHA-1. The runtime has no crypto
# package, so the key is read from its DER form and signed with plain pow(),
# as in the inventory-boxes stack.
def der_read(data, offset):
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def der_sequence(data):
    items = []
    offset = 0
    while offset < len(data):
        tag, value, offset = der_read(data, offset)
        items.append((tag, value))
    return items


def load_rsa_private_key(pem):
    lines = [line.strip() for line in pem.strip().splitlines()]
    der = base64.b64decode("".join(line for line in lines if line and not line.startswith("-----")))
    _, body, _ = der_read(der, 0)
    items = der_sequence(body)
    if len(items) == 3 and items[2][0] == 0x04:
        # PKCS#8 wraps the PKCS#1 key in an OCTET STRING.
        _, body, _ = der_read(items[2][1], 0)
        items = der_sequence(body)
    numbers = [int.from_bytes(value, "big") for tag, value in items if tag == 0x02]
    _, n, e, d, p, q, dp, dq, qinv = numbers[:9]
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": dp, "dq": dq, "qinv": qinv}


def rsa_sha1_sign(message, key):
    size = (key["n"].bit_length() + 7) // 8
    digest = SHA1_DIGEST_INFO + hashlib.sha1(message).digest()
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest) - 3) + b"\x00" + digest
    m = int.from_bytes(encoded, "big")
    s1 = pow(m, key["dp"], key["p"])
    s2 = pow(m, key["dq"], key["q"])
    h = (key["qinv"] * (s1 - s2)) % key["p"]
    return (s2 + h * key["q"]).to_bytes(size, "big")


class _HtmlText(html.parser.HTMLParser):
    BLOCKS = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "hr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "title"):
            self.skip += 1
        elif tag in self.BLOCKS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title"):
            self.skip = max(0, self.skip - 1)
        elif tag in self.BLOCKS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(re.sub(r"\s+", " ", data))


def html_text(markup):
    parser = _HtmlText()
    parser.feed(markup)
    parser.close()
    lines = [line.strip() for line in "".join(parser.parts).splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def logged_alias_address(item):
    return f"{item.get('alias')}@{item.get('alias_domain') or domain_name()}"


def public_alias(item):
    return {
        "local": item["sk"],
        "domain": alias_domain(item),
        "address": alias_address(item),
        "comment": item.get("comment") or "",
        "forward_to": item.get("forward_to") or "",
        "destination": destination(item),
        "sender_name": item.get("sender_name") or "",
        "active": bool(item.get("active")),
        "created_at": item.get("created_at") or "",
        "updated_at": item.get("updated_at") or "",
        "forwarded": int(item.get("forwarded") or 0),
        "last_at": item.get("last_at") or "",
    }


# Whether SES may send to the address while the account is in the sandbox:
# the address itself or its domain is a verified identity.
def destination_status(address):
    if not mail_enabled():
        return "none"
    for identity in (address, address.split("@")[1]):
        try:
            found = ses().get_email_identity(EmailIdentity=identity)
        except Exception as exc:
            if error_code(exc) == "NotFoundException":
                continue
            raise
        if found.get("VerifiedForSendingStatus"):
            return "verified"
        if identity == address:
            return "pending"
    return "none"


def production_access():
    if not mail_enabled():
        return False
    try:
        return bool(ses().get_account().get("ProductionAccessEnabled"))
    except Exception:
        logger.exception("SES account status is unknown")
        return False


# Only a verified email from the Cognito token counts: an unverified one could
# be any address.
def actor(event):
    claims = event.get("requestContext", {}).get("authorizer", {}).get("jwt", {}).get("claims", {})
    address = str(claims.get("email") or "").lower()
    if not address or str(claims.get("email_verified")).lower() != "true":
        raise ApiError(403, "email_not_verified")
    return address


def clean_local(value):
    local = str(value).strip().lower()
    if not ALIAS_RE.fullmatch(local) or local in RESERVED or relay_code(local):
        raise ApiError(400, "bad_local")
    return local


def clean_comment(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ApiError(400, "bad_comment_type")
    value = value.strip()
    if len(value) > 500:
        raise ApiError(400, "comment_too_long")
    return value


# A name, not an address: "@" or angle brackets in it would look like a forged
# sender again, and line breaks would break the header.
def clean_sender_name(value):
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise ApiError(400, "bad_sender_name_type")
    name = " ".join(value.split())
    if len(name) > 100 or any(char in name for char in "@<>\"") or any(ord(char) < 32 for char in value if char not in " \t"):
        raise ApiError(400, "bad_sender_name")
    return name


def clean_forward(value):
    if value in (None, ""):
        return ""
    address = str(value).strip().lower()
    if not EMAIL_RE.fullmatch(address):
        raise ApiError(400, "bad_forward")
    if address.split("@")[1] in alias_domains():
        raise ApiError(400, "forward_loop")
    return address


# A correspondent: an address outside the alias domains, where mail would
# loop back here.
def clean_recipient(value):
    address = str(value or "").strip().lower()
    if not EMAIL_RE.fullmatch(address) or address.split("@")[1] in alias_domains():
        raise ApiError(400, "bad_recipient")
    return address


# A correspondent's name, shown with their address in To; the same rules as a
# sender name.
def clean_name(value):
    try:
        return clean_sender_name(value)
    except ApiError as exc:
        raise ApiError(400, "bad_name") from exc


def clean_subject(value):
    if value in (None, ""):
        return ""
    if not isinstance(value, str) or len(value) > SUBJECT_LIMIT or any(char in value for char in "\r\n"):
        raise ApiError(400, "bad_subject")
    return value.strip()


# A domain of the aliases; empty is DOMAIN.
def clean_domain(value, status=400):
    domain = str(value or "").strip().lower() or domain_name()
    if domain not in alias_domains():
        raise ApiError(status, "bad_domain")
    return domain


# limit is in characters; a new message takes more than the rest of the API.
def body_json(event, limit=10_000):
    raw = event.get("body") or ""
    if event.get("isBase64Encoded") and raw:
        raw = base64.b64decode(raw).decode("utf-8")
    if len(raw) > limit:
        raise ApiError(413, "too_large")
    value = json.loads(raw) if raw else {}
    if not isinstance(value, dict):
        raise ApiError(400, "bad_json_object")
    return value


def response(status, payload):
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json; charset=utf-8", "cache-control": "no-store"},
        "body": json.dumps(payload, ensure_ascii=False),
    }


# Helpers ------------------------------------------------------------------

def reply_code(local, sender):
    digest = hashlib.sha256(f"{local}\n{sender.lower()}".encode()).digest()
    return base64.b32encode(digest).decode().lower()[:CODE_LENGTH]


# The address a forwarded message comes from: the sender's address with "@"
# and dots spelled out, then the code, as Apple's relay does:
# office@shop.test -> office_at_shop_test_<code>@domain. Only the code counts
# when a reply comes back.
def relay_address(sender, code, domain=None):
    readable = re.sub(r"[^a-z0-9]+", "_", sender.lower().replace("@", "_at_")).strip("_")
    readable = readable[:64 - CODE_LENGTH - 1].rstrip("_") or "r"
    return f"{readable}_{code}@{domain or domain_name()}"


# The code of a relay address (local part or whole address), in the current or
# the older r-<code> form; None for anything else.
def relay_code(value):
    local = str(value or "").strip().lower().split("@")[0]
    if local.startswith(REPLY_PREFIX):
        return local[len(REPLY_PREFIX):] or None
    match = RELAY_RE.fullmatch(local)
    return match.group(1) if match else None


def parse(raw):
    return email.message_from_bytes(raw, policy=email.policy.SMTP)


def first_address(value):
    for name, address in email.utils.getaddresses([str(value or "")]):
        if "@" in address:
            return name, address.lower()
    return "", ""


def drop_headers(message, names):
    for name in names:
        while name in message:
            del message[name]
    prefixes = tuple(prefix.lower() for prefix in DROPPED_PREFIXES)
    for name in {key for key in message.keys() if key.lower().startswith(prefixes)}:
        del message[name]


# The sender as the display name of the reply address: the sender's own name,
# or the address when there is no name. An address inside a display name that
# differs from the real one is a classic spoofing sign, so "@" becomes " at ".
def shown_sender(name, address):
    name = (name or "").strip()
    if name and "@" not in name:
        return name
    return address.replace("@", " at ")


def verdict(receipt, name):
    return ((receipt.get(name) or {}).get("status") or "").upper()


# SES puts FromEmailAddress into the From of a raw message as it is, so it
# carries the display name too: a bare address would drop the name.
# message is a parsed message or, once signed, its exact bytes: a signed
# message must not be serialized again.
def send(source, destinations, message):
    data = message if isinstance(message, bytes) else message.as_bytes(policy=email.policy.SMTP)
    ses().send_email(
        FromEmailAddress=source,
        Destination={"ToAddresses": destinations},
        Content={"Raw": {"Data": data}},
    )


def error_code(exc):
    data = getattr(exc, "response", None)
    return data.get("Error", {}).get("Code", "") if isinstance(data, dict) else ""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set")
    return value


# The domain of the page, and the first domain of the aliases.
def domain_name():
    return env("DOMAIN").lower()


def mail_enabled():
    return os.environ.get("MAIL_ENABLED", "true").lower() == "true"


# Whether a cap of the installation (an env number, 0 or unset for none) is
# reached for the items of one partition.
def limit_reached(pk, name):
    limit = int(os.environ.get(name) or 0)
    return limit > 0 and len(query_all(pk)) >= limit


# Every alias domain, DOMAIN first.
def alias_domains():
    others = [domain.strip().lower() for domain in os.environ.get("DOMAINS", "").split(",") if domain.strip()]
    return [domain_name()] + [domain for domain in others if domain != domain_name()]


def forward_to():
    return env("FORWARD_TO").lower()


def s3():
    global _s3
    if _s3 is None:
        import boto3
        _s3 = boto3.client("s3")
    return _s3


def ses():
    global _ses
    if _ses is None:
        import boto3
        _ses = boto3.client("sesv2")
    return _ses


# SES v2 has no call that resends the verification email of an address; v1
# VerifyEmailIdentity creates the identity or sends the link again.
def ses_v1():
    global _ses_v1
    if _ses_v1 is None:
        import boto3
        _ses_v1 = boto3.client("ses")
    return _ses_v1


def ssm():
    global _ssm
    if _ssm is None:
        import boto3
        _ssm = boto3.client("ssm")
    return _ssm


def table():
    global _table
    if _table is None:
        import boto3
        _table = boto3.resource("dynamodb").Table(env("TABLE_NAME"))
    return _table


# Versions -----------------------------------------------------------------

# The version of this deployment (VERSION) and the releases of the demo
# repository (RELEASES_REPOSITORY, owner/name) that came after it. They come
# from the Atom feed of the repository's GitHub releases, a public page that
# the hourly limit of the REST API, shared by every function behind Lambda's
# addresses, does not touch. The list stays an hour in the warm function, and
# the last one read serves while GitHub does not answer.
RELEASES_SECONDS = 3600
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
ATOM = "{http://www.w3.org/2005/Atom}"
_releases = None


def version_info():
    current = os.environ.get("VERSION", "")
    repository = os.environ.get("RELEASES_REPOSITORY", "")
    info = {
        "version": current,
        "repository": repository,
        "url": f"https://github.com/{repository}/releases" if repository else None,
        "latest": None,
        "newer": [],
        "checked_at": None,
        "error": None,
    }
    if not repository:
        return info
    try:
        releases, checked_at = github_releases(repository)
    except Exception:
        logger.exception("releases of %s not read", repository)
        info["error"] = "unavailable"
        return info
    info["checked_at"] = checked_at
    info["latest"] = releases[0]["version"] if releases else None
    info["newer"] = [release for release in releases if version_key(release["version"]) > version_key(current)]
    return info


def version_key(value):
    match = VERSION_RE.match(value or "")
    return tuple(int(part) for part in match.groups()) if match else ()


def github_releases(repository):
    global _releases
    now = time.time()
    if _releases and _releases[0] == repository and now - _releases[1] < RELEASES_SECONDS:
        return _releases[2], _releases[3]
    try:
        request = urllib.request.Request(
            f"https://github.com/{repository}/releases.atom",
            headers={"Accept": "application/atom+xml", "User-Agent": "release-check (+https://github.com/" + repository + ")"},
        )
        with urllib.request.urlopen(request, timeout=5) as answer:
            releases = parse_releases(answer.read(2_000_000))
    except Exception:
        if _releases and _releases[0] == repository:
            logger.warning("releases of %s not read; the list of %s serves", repository, _releases[3], exc_info=True)
            return _releases[2], _releases[3]
        raise
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    _releases = (repository, now, releases, checked_at)
    return releases, checked_at


# The entries of the feed whose tag is a version, newest version first, with
# their notes as plain text.
def parse_releases(feed):
    import xml.etree.ElementTree as ElementTree

    releases = []
    for entry in ElementTree.fromstring(feed).findall(ATOM + "entry"):
        link = entry.find(ATOM + "link")
        url = link.get("href", "") if link is not None else ""
        version = unquote(url.rstrip("/").rsplit("/", 1)[-1])
        if not version_key(version):
            continue
        releases.append({
            "version": version,
            "title": (entry.findtext(ATOM + "title") or version).strip(),
            "date": (entry.findtext(ATOM + "updated") or "")[:10],
            "url": url,
            "notes": release_notes(entry.findtext(ATOM + "content") or "")[:4000],
        })
    releases.sort(key=lambda release: version_key(release["version"]), reverse=True)
    return releases


class ReleaseNotes(html.parser.HTMLParser):
    BREAKS = {"p", "div", "br", "ul", "ol", "pre", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote"}

    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == "li":
            self.parts.append("\n• ")
        elif tag in self.BREAKS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self.BREAKS:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def release_notes(value):
    parser = ReleaseNotes()
    parser.feed(value)
    parser.close()
    lines = (" ".join(line.split()) for line in "".join(parser.parts).splitlines())
    return "\n".join(line for line in lines if line)
