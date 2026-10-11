# Mail: received messages under incoming/ (kept mail_retention_days), the
# message log under messages/ and the attachments of logged messages under
# attachments/, which only the page or the demo reset deletes. CloudFront
# reads attachments/ for holders of the signed cookie.
resource "aws_s3_bucket" "mail" {
  #checkov:skip=CKV_AWS_145:SSE-S3 is enough here. A customer managed key would add a monthly charge.
  #checkov:skip=CKV_AWS_144:A personal message log. Cross-region replication is not needed.
  #checkov:skip=CKV2_AWS_62:SES invokes the function itself. Event notifications are not needed.
  #checkov:skip=CKV_AWS_18:Access logs of a bucket with one writer and one reader are not worth a second bucket.
  #checkov:skip=CKV_AWS_21:Messages are written once and deleted on purpose. Versioning would only keep deleted mail longer.
  bucket        = local.mail_bucket
  force_destroy = var.demo
}

resource "aws_s3_bucket_public_access_block" "mail" {
  bucket                  = aws_s3_bucket.mail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "mail" {
  bucket = aws_s3_bucket.mail.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mail" {
  bucket = aws_s3_bucket.mail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "mail" {
  bucket = aws_s3_bucket.mail.id

  # The message log under messages/ and attachments/ does not expire.
  rule {
    id     = "expire-mail"
    status = "Enabled"

    filter {
      prefix = local.mail_prefix
    }

    expiration {
      days = var.mail_retention_days
    }
  }

  rule {
    id     = "abort-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "mail" {
  bucket = aws_s3_bucket.mail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      local.mail ? [{
        Sid       = "AllowSesPut"
        Effect    = "Allow"
        Principal = { Service = "ses.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.mail.arn}/${local.mail_prefix}*"
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = local.account_id
            "AWS:SourceArn"     = local.receipt_rule_arn
          }
        }
      }] : [],
      [
        {
          Sid       = "AllowCloudFrontAttachments"
          Effect    = "Allow"
          Principal = { Service = "cloudfront.amazonaws.com" }
          Action    = "s3:GetObject"
          Resource  = "${aws_s3_bucket.mail.arn}/${local.attachments_prefix}*"
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
          Resource  = [aws_s3_bucket.mail.arn, "${aws_s3_bucket.mail.arn}/*"]
          Condition = {
            Bool = { "aws:SecureTransport" = "false" }
          }
        },
      ],
    )
  })

  depends_on = [aws_s3_bucket_public_access_block.mail]
}
