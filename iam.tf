data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "relay" {
  #checkov:skip=CKV_AWS_111:VerifyEmailIdentity and GetAccount take no resource ARN.
  #checkov:skip=CKV_AWS_356:VerifyEmailIdentity and GetAccount take no resource ARN.
  statement {
    sid = "Logs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.relay.arn}:*"]
  }

  statement {
    sid       = "ReadMail"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.mail.arn}/${local.mail_prefix}*", "${aws_s3_bucket.mail.arn}/${local.messages_prefix}*"]
  }

  # The message log: a copy of each forwarded message and reply, and its
  # attachments as objects of their own; the page deletes them.
  statement {
    sid = "MessageLog"
    actions = [
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.mail.arn}/${local.messages_prefix}*", "${aws_s3_bucket.mail.arn}/${local.attachments_prefix}*"]
  }

  statement {
    sid = "Table"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:DeleteItem",
      "dynamodb:BatchWriteItem",
      "dynamodb:Query",
    ]
    resources = [aws_dynamodb_table.relay.arn]
  }

  # The private key that signs the CloudFront cookie for /attachments/*.
  statement {
    sid       = "ReadAttachmentsSigningKey"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.attachments_signing_key.arn]
  }

  # Mail only. While the account is in the SES sandbox SES also checks each
  # recipient, and every alias may forward to an address of its own, so all
  # identities of the region count. The page shows whether a forwarding
  # address is verified and asks SES to send it a link.
  dynamic "statement" {
    for_each = local.mail ? [1] : []

    content {
      sid = "SendMail"
      actions = [
        "ses:SendEmail",
        "ses:SendRawEmail",
        "ses:GetEmailIdentity",
      ]
      resources = ["arn:aws:ses:${var.region}:${local.account_id}:identity/*"]
    }
  }

  dynamic "statement" {
    for_each = local.mail ? [1] : []

    content {
      sid = "VerifyAddressesAndReadTheSandbox"
      actions = [
        "ses:VerifyEmailIdentity",
        "ses:GetAccount",
      ]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role" "relay" {
  name               = "${local.name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy" "relay" {
  name   = "${local.name}-lambda"
  role   = aws_iam_role.relay.id
  policy = data.aws_iam_policy_document.relay.json
}
