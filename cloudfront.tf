# What every distribution of the page shares (site.tf makes one per domain,
# or one on the CloudFront address without domains):
# access to the two buckets, the key that signs the attachment cookie, and
# the cache and header policies.

resource "aws_cloudfront_origin_access_control" "web" {
  provider                          = aws.global
  name                              = local.web_bucket
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_origin_access_control" "mail" {
  provider                          = aws.global
  name                              = local.mail_bucket
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# Attachments: CloudFront lets a request to /attachments/* through only with
# cookies signed by this key. The API signs them after API Gateway has checked
# the Cognito token; the Lambda reads the private key from SSM.
resource "tls_private_key" "attachments" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_cloudfront_public_key" "attachments" {
  provider    = aws.global
  name        = "${local.name}-attachments"
  encoded_key = tls_private_key.attachments.public_key_pem
}

resource "aws_cloudfront_key_group" "attachments" {
  provider = aws.global
  name     = "${local.name}-attachments"
  items    = [aws_cloudfront_public_key.attachments.id]
}

resource "aws_ssm_parameter" "attachments_signing_key" {
  #checkov:skip=CKV_AWS_337:The AWS managed SSM key is enough for this CloudFront signing key.
  name        = "/${local.name}/cloudfront-private-key"
  description = "Private key that signs the CloudFront cookie for message attachments."
  type        = "SecureString"
  value       = tls_private_key.attachments.private_key_pem
}

resource "aws_cloudfront_cache_policy" "web" {
  provider    = aws.global
  name        = "${local.name}-web"
  comment     = "Short cache for the page. API responses are not cached."
  default_ttl = 0
  max_ttl     = 86400
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    enable_accept_encoding_brotli = true
    enable_accept_encoding_gzip   = true

    headers_config {
      header_behavior = "none"
    }

    cookies_config {
      cookie_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }
  }
}

resource "aws_cloudfront_response_headers_policy" "web" {
  provider = aws.global
  name     = "${local.name}-web"

  security_headers_config {
    content_type_options {
      override = true
    }

    frame_options {
      frame_option = "DENY"
      override     = true
    }

    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      override                   = true
      preload                    = true
    }

    referrer_policy {
      referrer_policy = "no-referrer"
      override        = true
    }

    content_security_policy {
      content_security_policy = local.csp
      override                = true
    }
  }
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  provider = aws.global
  name     = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  provider = aws.global
  name     = "Managed-AllViewerExceptHostHeader"
}
