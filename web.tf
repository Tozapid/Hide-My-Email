# The page: static files in a private bucket, read only by CloudFront.
resource "aws_s3_bucket" "web" {
  #checkov:skip=CKV_AWS_145:SSE-S3 is enough for the static page. A customer managed key would add a monthly charge.
  #checkov:skip=CKV_AWS_144:The page source is in git. Cross-region replication is not needed.
  #checkov:skip=CKV2_AWS_62:This bucket only serves the page. Event notifications are not needed.
  #checkov:skip=CKV_AWS_18:CloudFront and the API carry the useful access trail. A second log bucket is not worth it here.
  #checkov:skip=CKV_AWS_21:The page source is in git; each apply uploads it again.
  bucket        = local.web_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "web" {
  bucket                  = aws_s3_bucket.web.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "web" {
  bucket = aws_s3_bucket.web.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "web" {
  bucket = aws_s3_bucket.web.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "web" {
  bucket = aws_s3_bucket.web.id

  rule {
    id     = "abort-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "web" {
  bucket = aws_s3_bucket.web.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudFrontRead"
        Effect    = "Allow"
        Principal = { Service = "cloudfront.amazonaws.com" }
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.web.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = local.distribution_arns
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.web.arn, "${aws_s3_bucket.web.arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.web]
}

locals {
  web_assets = {
    "index.html"  = "text/html; charset=utf-8"
    "app.js"      = "text/javascript; charset=utf-8"
    "i18n.js"     = "text/javascript; charset=utf-8"
    "styles.css"  = "text/css; charset=utf-8"
    "favicon.svg" = "image/svg+xml"
    # The BIMI logo of the domain, SVG Tiny PS.
    "bimi.svg" = "image/svg+xml"
  }
}

resource "aws_s3_object" "web" {
  for_each = local.web_assets

  bucket        = aws_s3_bucket.web.id
  key           = each.key
  source        = "${path.module}/web/${each.key}"
  etag          = filemd5("${path.module}/web/${each.key}")
  content_type  = each.value
  cache_control = "no-cache"
}

resource "aws_s3_object" "config" {
  bucket        = aws_s3_bucket.web.id
  key           = "config.js"
  content_type  = "text/javascript; charset=utf-8"
  cache_control = "no-cache"
  # The demo publishes its sign-in on the sign-in screen; nothing else is.
  content = templatefile("${path.module}/web/config.js.tftpl", {
    region       = var.region
    user_pool_id = aws_cognito_user_pool.main.id
    client_id    = aws_cognito_user_pool_client.web.id
    demo = jsonencode(var.demo ? {
      email    = var.admin_email
      password = var.admin_password
      reset    = local.reset
    } : null)
  })
}
