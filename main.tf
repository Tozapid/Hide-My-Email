# The module makes no providers: the caller passes aws, in the region of
# every resource but CloudFront, and aws.global in us-east-1, where CloudFront
# and its certificate live (see README).
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

locals {
  name       = var.name
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region

  # Mail is on once there are domains. Without them (the demo) nothing is
  # received or sent, and the aliases use a placeholder domain.
  mail          = length(var.domains) > 0
  alias_domains = local.mail ? [for domain in var.domains : domain.name] : [var.demo_domain]

  # One distribution of the page per domain but those for mail only; without
  # domains, one on the default *.cloudfront.net address.
  sites = local.mail ? { for domain in var.domains : domain.name => domain if !domain.mail_only } : { default = null }
  # The domains for mail only: their SES identity is another stack's.
  mail_only_domains = [for domain in var.domains : domain.name if domain.mail_only]

  # Route 53 zones of the domains that have one.
  zones = toset([for domain in var.domains : domain.route53_zone if domain.route53_zone != null])

  reset = var.reset_delay_hours > 0

  # The version of this deployment: the newest entry of CHANGELOG.md
  # (## vX.Y.Z, then optionally " — " and a date or a title). After main is
  # deployed, CI tags and releases it on GitHub.
  version = regex("(?m)^## (v[0-9]+\\.[0-9]+\\.[0-9]+)(?:\\s|$)", file("${path.module}/CHANGELOG.md"))[0]

  mail_bucket        = var.mail_bucket_name != "" ? var.mail_bucket_name : "${local.name}-mail-${local.account_id}"
  web_bucket         = "${local.name}-web-${local.account_id}"
  mail_prefix        = "incoming/"
  messages_prefix    = "messages/"
  attachments_prefix = "attachments/"

  # The ARN of the receipt rule is known before the rule exists, so the bucket
  # policy and the Lambda permission can name it without a dependency cycle.
  receipt_rule_arn = "arn:aws:ses:${local.region}:${local.account_id}:receipt-rule-set/${local.name}:receipt-rule/relay"

  distribution_arns = [for site in module.site : site.distribution_arn]

  csp = join("; ", [
    "default-src 'self'",
    # Only the two libraries of the page, not all of jsDelivr: with a whole
    # CDN allowed, injected markup could load any package from it.
    "script-src 'self' https://cdn.jsdelivr.net/npm/amazon-cognito-identity-js@6.3.15/ https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self' https://cognito-idp.${local.region}.amazonaws.com",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ])
}

data "aws_route53_zone" "domain" {
  for_each = local.zones

  name         = each.value
  private_zone = false
}
