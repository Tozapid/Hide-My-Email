# OpenPGP signatures of what the aliases send (lambda/pgp.py). The private
# key of an alias is never stored: the function derives it from this secret
# and the alias, so the secret is the one thing to keep. A new secret gives
# every alias a new key, and the signatures of mail already sent would no
# longer check against the keys in the Web Key Directory: it is kept from
# being destroyed, and it stays when pgp_enabled is false, so that PGP turned
# back on gives the same keys.
resource "random_password" "pgp" {
  length  = 64
  special = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ssm_parameter" "pgp_secret" {
  #checkov:skip=CKV_AWS_337:The AWS managed SSM key is enough for this secret.
  name        = "/${local.name}/pgp-secret"
  description = "Secret the OpenPGP signing keys of the aliases are derived from."
  type        = "SecureString"
  value       = random_password.pgp.result
}
