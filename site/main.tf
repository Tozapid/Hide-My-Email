# The page at one domain, or at the CloudFront address without one: an ACM
# certificate of its own and a distribution with three origins. The bucket of the page is the default, /attachments/* comes
# from the mail bucket only with the signed cookie, /api/* goes to API Gateway.
# Nothing is shared between domains but the origins and the policies.

resource "aws_acm_certificate" "this" {
  count = var.domain == null ? 0 : 1

  provider          = aws.global
  domain_name       = var.domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "certificate" {
  for_each = var.domain == null || var.route53_zone_id == null ? {} : {
    for option in aws_acm_certificate.this[0].domain_validation_options : option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  }

  allow_overwrite = true
  zone_id         = var.route53_zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
}

# Without a Route 53 zone this waits until the record is in place at the DNS
# host: the first time, apply the certificate alone (-target) and add the
# record from the output certificate_validation_records.
resource "aws_acm_certificate_validation" "this" {
  count = var.domain == null ? 0 : 1

  provider                = aws.global
  certificate_arn         = aws_acm_certificate.this[0].arn
  validation_record_fqdns = var.route53_zone_id == null ? null : [for record in aws_route53_record.certificate : record.fqdn]

  timeouts {
    create = "30m"
  }
}

resource "aws_cloudfront_distribution" "this" {
  #checkov:skip=CKV_AWS_374:Geo restriction is not required for this private page.
  #checkov:skip=CKV_AWS_68:A WAFv2 web ACL alone would cost more than the rest of the stack.
  #checkov:skip=CKV2_AWS_47:No WAFv2 WebACL is attached.
  #checkov:skip=CKV_AWS_310:Two S3 origins and one API origin, each with its own path. A failover group is not needed.
  #checkov:skip=CKV_AWS_86:The access logs are standard logging v2 (access-logs.tf); the legacy logging block needs a bucket ACL.
  #checkov:skip=CKV_AWS_305:Geo restriction is not required for this private page.
  #checkov:skip=CKV_AWS_174:Without a domain the default CloudFront certificate allows no minimum TLS version; with one it is TLSv1.2_2021.
  provider            = aws.global
  enabled             = true
  is_ipv6_enabled     = true
  aliases             = var.domain == null ? [] : [var.domain]
  comment             = var.comment
  price_class         = "PriceClass_100"
  default_root_object = "index.html"
  http_version        = "http2and3"
  wait_for_deployment = true

  origin {
    domain_name              = var.origins.web_bucket_domain
    origin_id                = "web"
    origin_access_control_id = var.origins.web_oac_id
    connection_attempts      = 3
    connection_timeout       = 10
  }

  origin {
    domain_name              = var.origins.mail_bucket_domain
    origin_id                = "mail"
    origin_access_control_id = var.origins.mail_oac_id
    connection_attempts      = 3
    connection_timeout       = 10
  }

  origin {
    domain_name = var.origins.api_domain
    origin_id   = "api"

    # The API does not see the host the page was asked on; the Web Key
    # Directory of the function needs it to serve the keys of this domain.
    # Without a domain (the demo) the function takes the one of its aliases.
    dynamic "custom_header" {
      for_each = var.web_key_directory && var.domain != null ? [var.domain] : []
      content {
        name  = "X-Hide-My-Email-Site"
        value = custom_header.value
      }
    }

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 30
      origin_keepalive_timeout = 5
    }
  }

  default_cache_behavior {
    target_origin_id       = "web"
    allowed_methods        = ["GET", "HEAD", "OPTIONS"]
    cached_methods         = ["GET", "HEAD"]
    viewer_protocol_policy = "redirect-to-https"
    compress               = true

    cache_policy_id            = var.policies.web_cache_id
    response_headers_policy_id = var.policies.response_headers_id
  }

  # Not cached: a deleted message must stop serving its attachments at once.
  ordered_cache_behavior {
    path_pattern               = "/attachments/*"
    target_origin_id           = "mail"
    allowed_methods            = ["GET", "HEAD"]
    cached_methods             = ["GET", "HEAD"]
    viewer_protocol_policy     = "redirect-to-https"
    compress                   = false
    cache_policy_id            = var.policies.caching_disabled_id
    response_headers_policy_id = var.policies.response_headers_id
    trusted_key_groups         = [var.policies.attachments_key_group_id]
  }

  ordered_cache_behavior {
    path_pattern             = "/api/*"
    target_origin_id         = "api"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    viewer_protocol_policy   = "redirect-to-https"
    compress                 = true
    cache_policy_id          = var.policies.caching_disabled_id
    origin_request_policy_id = var.policies.all_viewer_except_host_id
  }

  # The Web Key Directory (direct method): the OpenPGP keys of the aliases of
  # this domain, which mail clients look up by address to check signatures.
  dynamic "ordered_cache_behavior" {
    for_each = var.web_key_directory ? ["/.well-known/openpgpkey/*"] : []
    content {
      path_pattern             = ordered_cache_behavior.value
      target_origin_id         = "api"
      allowed_methods          = ["GET", "HEAD", "OPTIONS"]
      cached_methods           = ["GET", "HEAD"]
      viewer_protocol_policy   = "redirect-to-https"
      compress                 = false
      cache_policy_id          = var.policies.caching_disabled_id
      origin_request_policy_id = var.policies.all_viewer_except_host_id
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  # Without a domain CloudFront's own certificate for *.cloudfront.net, which
  # allows no minimum protocol version.
  viewer_certificate {
    cloudfront_default_certificate = var.domain == null
    acm_certificate_arn            = var.domain == null ? null : aws_acm_certificate_validation.this[0].certificate_arn
    ssl_support_method             = var.domain == null ? null : "sni-only"
    minimum_protocol_version       = var.domain == null ? null : "TLSv1.2_2021"
  }
}

# In a Route 53 zone the page answers at the domain itself, next to its MX
# record.
resource "aws_route53_record" "alias" {
  for_each = var.domain == null || var.route53_zone_id == null ? toset([]) : toset(["A", "AAAA"])

  zone_id = var.route53_zone_id
  name    = var.domain
  type    = each.value

  alias {
    name                   = aws_cloudfront_distribution.this.domain_name
    zone_id                = aws_cloudfront_distribution.this.hosted_zone_id
    evaluate_target_health = false
  }
}
