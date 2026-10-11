"""Hourly reset of the public demo: back to a fresh deployment.

- Every item of the table goes: aliases, reply codes, the message log and the
  API keys; so do the copies of logged messages and their attachments.
- The example aliases and messages of seed.json are written again, with times
  counted back from now, so the demo always looks recent. The messages go
  through the same code as real ones: the log record, the copy, the
  attachments and the reply code, so search by a relay address works too.
- The demo user gets the published password back, two-step sign-in off, the
  default language and is signed out everywhere; any other user is deleted.
"""

import email.message
import email.policy
import email.utils
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import hide_my_email as app

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SEED = Path(__file__).with_name("seed.json")

_cognito = None
_ssm = None


def handler(event, context):
    seed = json.loads(SEED.read_text(encoding="utf-8"))
    now = datetime.now(timezone.utc)
    removed = wipe_table()
    deleted = wipe_objects()
    aliases = write_aliases(seed.get("aliases", []), now)
    messages = write_messages(seed.get("messages", []), now)
    reset_users()
    logger.info("reset: %s items and %s objects removed, %s aliases and %s messages written", removed, deleted, aliases, messages)
    return {"removed": removed, "objects": deleted, "aliases": aliases, "messages": messages}


# Data ---------------------------------------------------------------------

def wipe_table():
    keys = []
    kwargs = {"ProjectionExpression": "pk, sk"}
    while True:
        page = app.table().scan(**kwargs)
        keys.extend({"pk": item["pk"], "sk": item["sk"]} for item in page.get("Items", []))
        if not page.get("LastEvaluatedKey"):
            break
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
    with app.table().batch_writer() as batch:
        for key in keys:
            batch.delete_item(Key=key)
    return len(keys)


def wipe_objects():
    bucket = app.env("MAIL_BUCKET")
    count = 0
    for prefix in (app.env("MESSAGES_PREFIX"), app.env("ATTACHMENTS_PREFIX")):
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        while True:
            page = app.s3().list_objects_v2(**kwargs)
            keys = [{"Key": entry["Key"]} for entry in page.get("Contents", [])]
            if keys:
                app.s3().delete_objects(Bucket=bucket, Delete={"Objects": keys, "Quiet": True})
                count += len(keys)
            if not page.get("IsTruncated"):
                break
            kwargs["ContinuationToken"] = page["NextContinuationToken"]
    return count


def iso(moment):
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def write_aliases(aliases, now):
    domain = app.domain_name()
    for entry in aliases:
        created = iso(now - timedelta(minutes=entry.get("created_minutes_ago", 0)))
        item = {
            "pk": "ALIAS",
            "sk": entry["local"],
            "comment": entry.get("comment", ""),
            "active": entry.get("active", True),
            "created_at": created,
            "updated_at": created,
        }
        for field in ("forward_to", "sender_name"):
            if entry.get(field):
                item[field] = entry[field]
        if entry.get("pinned"):
            item["pinned"] = True
        if entry.get("domain") and entry["domain"] != domain:
            item["domain"] = entry["domain"]
        app.table().put_item(Item=item)
    return len(aliases)


# A seed message becomes what forwarding or a reply would have left behind:
# the raw message, its log record with attachments, the alias's counter and
# the reply code of the conversation.
def write_messages(messages, now):
    for entry in sorted(messages, key=lambda entry: -entry.get("minutes_ago", 0)):
        moment = now - timedelta(minutes=entry.get("minutes_ago", 0))
        alias = app.get_alias(entry["alias"])
        domain = app.alias_domain(alias)
        alias_address = f"{entry['alias']}@{domain}"
        sender_name, sender = email.utils.parseaddr(entry["from"])
        code = app.reply_code(entry["alias"], sender)
        relay = app.relay_address(sender, code, domain)
        outgoing = entry.get("direction") == "out"
        raw = build_message(entry, alias, alias_address, relay, moment)
        message_id = moment.strftime("%Y%m%dT%H%M%S%fZ") + "-" + secrets.token_hex(4)
        app.s3().put_object(Bucket=app.env("MAIL_BUCKET"), Key=app.env("MESSAGES_PREFIX") + message_id, Body=raw)
        count = app.store_attachments(message_id, app.parse(raw))
        app.table().put_item(Item={
            "pk": "MSG",
            "sk": message_id,
            "at": iso(moment),
            "size": len(raw),
            "attachments": count,
            "direction": "out" if outgoing else "in",
            "alias": entry["alias"],
            "alias_domain": domain,
            "code": code,
            "relay": relay,
            "from_name": (alias or {}).get("sender_name", "") if outgoing else sender_name,
            "from_address": alias_address if outgoing else sender,
            "to_name": sender_name if outgoing else "",
            "to_address": sender if outgoing else alias_address,
            "delivered_to": sender if outgoing else app.destination(alias or {}),
            "subject": entry.get("subject", ""),
            "spam": bool(entry.get("spam")),
        })
        app.table().put_item(Item={"pk": "REPLY", "sk": code, "alias": entry["alias"], "sender": sender, "name": sender_name, "updated_at": iso(moment)})
        if not outgoing:
            app.table().update_item(
                Key={"pk": "ALIAS", "sk": entry["alias"]},
                UpdateExpression="SET #forwarded = if_not_exists(#forwarded, :zero) + :one, #last_at = :now",
                ExpressionAttributeNames={"#forwarded": "forwarded", "#last_at": "last_at"},
                ExpressionAttributeValues={":zero": 0, ":one": 1, ":now": iso(moment)},
            )
    return len(messages)


def build_message(entry, alias, alias_address, relay, moment):
    message = email.message.EmailMessage(policy=email.policy.SMTP)
    if entry.get("direction") == "out":
        message["From"] = email.utils.formataddr(((alias or {}).get("sender_name", ""), alias_address))
        message["To"] = entry["from"]
    else:
        message["From"] = entry["from"]
        message["To"] = alias_address
    message["Subject"] = entry.get("subject", "")
    message["Date"] = email.utils.format_datetime(moment)
    message["Message-ID"] = email.utils.make_msgid(domain=relay.split("@")[1])
    if entry.get("html"):
        message.set_content(entry["html"], subtype="html")
    else:
        message.set_content(entry.get("text", ""))
    for attachment in entry.get("attachments", []):
        maintype, _, subtype = attachment.get("type", "text/plain").partition("/")
        message.add_attachment(attachment["content"].encode(), maintype=maintype, subtype=subtype, filename=attachment["name"])
    return message.as_bytes()


# Users --------------------------------------------------------------------

def reset_users():
    pool = env("USER_POOL_ID")
    demo = env("DEMO_EMAIL").lower()
    kwargs = {"UserPoolId": pool}
    username = None
    while True:
        page = cognito().list_users(**kwargs)
        for user in page.get("Users", []):
            address = next((attribute["Value"] for attribute in user.get("Attributes", []) if attribute["Name"] == "email"), "")
            if address.lower() == demo and username is None:
                username = user["Username"]
            else:
                cognito().admin_delete_user(UserPoolId=pool, Username=user["Username"])
        if not page.get("PaginationToken"):
            break
        kwargs["PaginationToken"] = page["PaginationToken"]
    if username is None:
        username = demo
        cognito().admin_create_user(
            UserPoolId=pool,
            Username=demo,
            MessageAction="SUPPRESS",
            UserAttributes=[{"Name": "email", "Value": demo}, {"Name": "email_verified", "Value": "true"}],
        )
    password = ssm().get_parameter(Name=env("DEMO_PASSWORD_PARAMETER"), WithDecryption=True)["Parameter"]["Value"]
    cognito().admin_set_user_password(UserPoolId=pool, Username=username, Password=password, Permanent=True)
    cognito().admin_set_user_mfa_preference(
        UserPoolId=pool,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
    )
    try:
        cognito().admin_delete_user_attributes(UserPoolId=pool, Username=username, UserAttributeNames=["locale"])
    except Exception:
        logger.info("no language to clear")
    cognito().admin_user_global_sign_out(UserPoolId=pool, Username=username)


def env(name):
    return app.env(name)


def cognito():
    global _cognito
    if _cognito is None:
        import boto3
        _cognito = boto3.client("cognito-idp")
    return _cognito


def ssm():
    global _ssm
    if _ssm is None:
        import boto3
        _ssm = boto3.client("ssm")
    return _ssm
