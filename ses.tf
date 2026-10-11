# Mail, only when there are domains. Each domain gets an SES identity: SES
# signs the forwarded mail and the replies with DKIM for it, and a custom
# MAIL FROM keeps SPF aligned too. Its DNS records go into its Route 53 zone
# when it names one; otherwise they are listed in the output dns_records.

locals {
  zoned_domains = { for domain in var.domains : domain.name => domain.route53_zone if domain.route53_zone != null }
}

resource "aws_sesv2_email_identity" "domain" {
  for_each = toset(local.mail ? local.alias_domains : [])

  email_identity = each.value
}

resource "aws_sesv2_email_identity_mail_from_attributes" "domain" {
  for_each = aws_sesv2_email_identity.domain

  email_identity         = each.value.email_identity
  mail_from_domain       = "bounce.${each.key}"
  behavior_on_mx_failure = "USE_DEFAULT_VALUE"
}

# The records every mail domain needs, in one list per domain; the zoned ones
# are written below, the others are output.
locals {
  mail_records = {
    for name in(local.mail ? local.alias_domains : []) : name => concat(
      [
        { key = "mx", type = "MX", name = name, value = "10 inbound-smtp.${var.region}.amazonaws.com" },
        { key = "mail-from-mx", type = "MX", name = "bounce.${name}", value = "10 feedback-smtp.${var.region}.amazonses.com" },
        { key = "mail-from-spf", type = "TXT", name = "bounce.${name}", value = "v=spf1 include:amazonses.com ~all" },
        # BIMI shows a logo only for DMARC quarantine or reject on all mail, so
        # the domain gets a record of its own instead of its parent's policy.
        { key = "dmarc", type = "TXT", name = "_dmarc.${name}", value = "v=DMARC1; p=quarantine; pct=100; adkim=r; aspf=r" },
        { key = "bimi", type = "TXT", name = "default._bimi.${name}", value = "v=BIMI1; l=https://${name}/bimi.svg; a=;" },
      ],
      # SES always gives three DKIM tokens; counting them keeps the keys known
      # before the identity exists.
      [
        for index in range(3) : {
          key   = "dkim-${index}"
          type  = "CNAME"
          name  = "${aws_sesv2_email_identity.domain[name].dkim_signing_attributes[0].tokens[index]}._domainkey.${name}"
          value = "${aws_sesv2_email_identity.domain[name].dkim_signing_attributes[0].tokens[index]}.dkim.amazonses.com"
        }
      ],
    )
  }
}

resource "aws_route53_record" "mail" {
  for_each = {
    for record in flatten([
      for name, records in local.mail_records : [
        for record in records : merge(record, { domain = name }) if contains(keys(local.zoned_domains), name)
      ]
    ]) : "${record.domain}/${record.key}" => record
  }

  zone_id = data.aws_route53_zone.domain[local.zoned_domains[each.value.domain]].zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 600
  records = [each.value.value]
}

# While the account is in the SES sandbox, SES only sends to verified
# addresses: AWS emails a link to forward_to that has to be opened once.
resource "aws_sesv2_email_identity" "forward_to" {
  count = local.mail && var.verify_forward_to ? 1 : 0

  email_identity = var.forward_to
}

# A region has one active receipt rule set. This one becomes it.
resource "aws_ses_receipt_rule_set" "main" {
  count = local.mail ? 1 : 0

  rule_set_name = local.name
}

resource "aws_ses_active_receipt_rule_set" "main" {
  count = local.mail ? 1 : 0

  rule_set_name = aws_ses_receipt_rule_set.main[0].rule_set_name
}

# Every address of the alias domains: the function decides what is an alias
# or a reply, and drops the rest. The message is stored first, because the
# Lambda action does not carry the body.
resource "aws_ses_receipt_rule" "relay" {
  count = local.mail ? 1 : 0

  name          = "relay"
  rule_set_name = aws_ses_receipt_rule_set.main[0].rule_set_name
  recipients    = local.alias_domains
  enabled       = true
  scan_enabled  = true
  tls_policy    = "Optional"

  s3_action {
    bucket_name       = aws_s3_bucket.mail.id
    object_key_prefix = local.mail_prefix
    position          = 1
  }

  lambda_action {
    function_arn    = aws_lambda_function.relay.arn
    invocation_type = "Event"
    position        = 2
  }

  depends_on = [
    aws_s3_bucket_policy.mail,
    aws_lambda_permission.ses,
  ]
}
