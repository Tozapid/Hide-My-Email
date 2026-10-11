# Users of the page. Nobody signs up: the first user is made here, more can be
# added in the Cognito console. Each user may turn on an authenticator app.
resource "aws_cognito_user_pool" "main" {
  name                     = local.name
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  mfa_configuration        = "OPTIONAL"

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = var.password_min_length
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 7
  }

  admin_create_user_config {
    allow_admin_create_user_only = true

    invite_message_template {
      email_subject = "Hide My Email"
      email_message = "Sign in to Hide My Email.<br><br>Email: {username}<br>Temporary password: {####}<br><br>You will choose your own password at first sign-in. The temporary one works for 7 days."
      sms_message   = "Hide My Email: {username}, temporary password {####}"
    }
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }
}

resource "aws_cognito_user_pool_client" "web" {
  name         = "${local.name}-web"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false
  explicit_auth_flows = [
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]

  prevent_user_existence_errors = "ENABLED"
  enable_token_revocation       = true

  access_token_validity  = 1
  id_token_validity      = 1
  refresh_token_validity = 30

  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }

  # locale is the language of the page, chosen in the account settings.
  read_attributes = ["email", "email_verified", "locale"]
  # The email names the user in the API, so users cannot change it.
  write_attributes = ["locale"]
}

# With admin_password the first user gets it as a permanent password and no
# email (the demo); without it Cognito mails a temporary one.
resource "aws_cognito_user" "admin" {
  user_pool_id             = aws_cognito_user_pool.main.id
  username                 = var.admin_email
  password                 = var.admin_password != "" ? var.admin_password : null
  message_action           = var.admin_password != "" ? "SUPPRESS" : null
  desired_delivery_mediums = var.admin_password != "" ? null : ["EMAIL"]

  attributes = {
    email          = var.admin_email
    email_verified = "true"
  }

  # The user may set their own password and language; apply must not take
  # them back (the demo reset does that on its own).
  lifecycle {
    ignore_changes = [password, temporary_password, attributes["locale"]]
  }
}
