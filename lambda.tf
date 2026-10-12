resource "aws_cloudwatch_log_group" "relay" {
  #checkov:skip=CKV_AWS_158:CloudWatch's own encryption is enough for these logs. A customer managed key would add a monthly charge.
  #checkov:skip=CKV_AWS_338:Thirty days is enough to look into a lost message and keeps the log bill small.
  name              = "/aws/lambda/${local.name}"
  retention_in_days = 30
}

locals {
  # The Python of the function; the layer is built for the same one.
  python = "3.14"
}

# The code: the function and its OpenPGP module, the tests stay out. Content
# sources give every file the same time, so the zip changes only with the code.
data "archive_file" "relay" {
  type = "zip"
  source {
    content  = file("${path.module}/lambda/hide_my_email.py")
    filename = "hide_my_email.py"
  }
  source {
    content  = file("${path.module}/lambda/pgp.py")
    filename = "pgp.py"
  }
  output_path = "${path.module}/.build/hide_my_email.zip"
  # The same zip on a workstation and in CI: the file mode is part of the hash.
  output_file_mode = "0644"
}

# The cryptography package for pgp.py, as a layer: the wheels of
# lambda/requirements.txt for the function's platform (Linux arm64), fetched
# with pip while Terraform plans. The runner needs python3 and access to PyPI;
# the same requirements give the same zip, so the layer changes only with them.
# Without PGP (pgp_enabled = false) there is no layer.
data "external" "layer" {
  count   = var.pgp_enabled ? 1 : 0
  program = ["python3", "${path.module}/lambda/build_layer.py"]
  query = {
    requirements = "${path.module}/lambda/requirements.txt"
    target       = "${path.module}/.build/layer"
    python       = local.python
  }
}

data "archive_file" "layer" {
  count            = var.pgp_enabled ? 1 : 0
  type             = "zip"
  source_dir       = data.external.layer[0].result.dir
  output_path      = "${path.module}/.build/hide_my_email_layer.zip"
  output_file_mode = "0644"
}

resource "aws_lambda_layer_version" "cryptography" {
  count                    = var.pgp_enabled ? 1 : 0
  layer_name               = "${local.name}-cryptography"
  description              = "cryptography for the OpenPGP signatures of the aliases"
  filename                 = data.archive_file.layer[0].output_path
  source_code_hash         = data.archive_file.layer[0].output_base64sha256
  compatible_runtimes      = ["python${local.python}"]
  compatible_architectures = ["arm64"]
}

resource "aws_lambda_function" "relay" {
  #checkov:skip=CKV_AWS_50:X-Ray is disabled to avoid extra cost on a low-traffic function.
  #checkov:skip=CKV_AWS_115:Reserved concurrency is left to the account pool.
  #checkov:skip=CKV_AWS_116:A failed message stays in S3 for mail_retention_days and its error in the logs.
  #checkov:skip=CKV_AWS_117:The function only calls public AWS endpoints for S3, DynamoDB, SES and SSM.
  #checkov:skip=CKV_AWS_173:Environment values are names and the forwarding address, not secrets.
  #checkov:skip=CKV_AWS_272:Code signing is not used for this function.
  function_name = local.name
  role          = aws_iam_role.relay.arn
  runtime       = "python${local.python}"
  architectures = ["arm64"]
  handler       = "hide_my_email.handler"
  memory_size   = 256
  timeout       = 60

  filename         = data.archive_file.relay.output_path
  source_code_hash = data.archive_file.relay.output_base64sha256
  layers           = aws_lambda_layer_version.cryptography[*].arn

  environment {
    variables = {
      VERSION                = local.version
      RELEASES_REPOSITORY    = var.releases_repository
      DOMAIN                 = local.alias_domains[0]
      DOMAINS                = join(",", local.alias_domains)
      FORWARD_TO             = var.forward_to
      MAIL_ENABLED           = tostring(local.mail)
      MAX_ALIASES            = tostring(var.max_aliases)
      MAX_TOKENS             = tostring(var.max_tokens)
      MAX_RELAYS             = tostring(var.max_relays)
      MAIL_BUCKET            = aws_s3_bucket.mail.id
      MAIL_PREFIX            = local.mail_prefix
      MESSAGES_PREFIX        = local.messages_prefix
      ATTACHMENTS_PREFIX     = local.attachments_prefix
      TABLE_NAME             = aws_dynamodb_table.relay.name
      SIGNING_KEY_PARAMETER  = aws_ssm_parameter.attachments_signing_key.name
      PGP_SECRET_PARAMETER   = aws_ssm_parameter.pgp_secret.name
      PGP                    = tostring(var.pgp_enabled)
      CLOUDFRONT_KEY_PAIR_ID = aws_cloudfront_public_key.attachments.id
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.relay.name
  }

  depends_on = [aws_iam_role_policy.relay]
}

# SES invokes the function asynchronously; Lambda retries a failure twice.
resource "aws_lambda_function_event_invoke_config" "relay" {
  function_name          = aws_lambda_function.relay.function_name
  maximum_retry_attempts = 2
}

resource "aws_lambda_permission" "ses" {
  count = local.mail ? 1 : 0

  statement_id   = "AllowSesReceiptRule"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.relay.function_name
  principal      = "ses.amazonaws.com"
  source_account = local.account_id
  source_arn     = local.receipt_rule_arn
}

# The version of this deployment: the newest entry of CHANGELOG.md
# (## vX.Y.Z, then optionally " — " and a date or a title). After main is
# deployed, CI releases it on GitHub.
locals {
  version = regex("(?m)^## (v[0-9]+\\.[0-9]+\\.[0-9]+)(?:\\s|$)", file("${path.module}/CHANGELOG.md"))[0]
}
