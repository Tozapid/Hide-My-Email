# One table: aliases (pk = ALIAS), reply codes (REPLY), the message log (MSG)
# and API keys (TOKEN). See the docstring of lambda/hide_my_email.py.
resource "aws_dynamodb_table" "relay" {
  #checkov:skip=CKV_AWS_119:An AWS owned key avoids a dedicated KMS charge.
  #checkov:skip=CKV_AWS_28:Point-in-time recovery is on outside the demo, which is rebuilt every hour.
  name         = local.name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "pk"
  range_key    = "sk"

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  # The demo is rebuilt every hour; a backup of it has nothing to bring back.
  point_in_time_recovery {
    enabled = !var.demo
  }

  server_side_encryption {
    enabled = true
  }
}
