# The demo kept its resources at the top of the state until the repository
# became a module (v1.9.0): its state keeps every resource, now under
# module.hide, and the page's distribution under module.hide.module.site.

moved {
  from = aws_apigatewayv2_api.http
  to   = module.hide.aws_apigatewayv2_api.http
}

moved {
  from = aws_apigatewayv2_authorizer.cognito
  to   = module.hide.aws_apigatewayv2_authorizer.cognito
}

moved {
  from = aws_apigatewayv2_integration.lambda
  to   = module.hide.aws_apigatewayv2_integration.lambda
}

moved {
  from = aws_apigatewayv2_route.api
  to   = module.hide.aws_apigatewayv2_route.api
}

moved {
  from = aws_apigatewayv2_route.public
  to   = module.hide.aws_apigatewayv2_route.public
}

moved {
  from = aws_apigatewayv2_route.addy_auth
  to   = module.hide.aws_apigatewayv2_route.addy_auth
}

moved {
  from = aws_apigatewayv2_route.web_key_directory
  to   = module.hide.aws_apigatewayv2_route.web_key_directory
}

moved {
  from = aws_cloudwatch_log_group.api
  to   = module.hide.aws_cloudwatch_log_group.api
}

moved {
  from = aws_apigatewayv2_stage.default
  to   = module.hide.aws_apigatewayv2_stage.default
}

moved {
  from = aws_lambda_permission.api
  to   = module.hide.aws_lambda_permission.api
}

moved {
  from = aws_cloudfront_origin_access_control.web
  to   = module.hide.aws_cloudfront_origin_access_control.web
}

moved {
  from = aws_cloudfront_origin_access_control.mail
  to   = module.hide.aws_cloudfront_origin_access_control.mail
}

moved {
  from = tls_private_key.attachments
  to   = module.hide.tls_private_key.attachments
}

moved {
  from = aws_cloudfront_public_key.attachments
  to   = module.hide.aws_cloudfront_public_key.attachments
}

moved {
  from = aws_cloudfront_key_group.attachments
  to   = module.hide.aws_cloudfront_key_group.attachments
}

moved {
  from = aws_ssm_parameter.attachments_signing_key
  to   = module.hide.aws_ssm_parameter.attachments_signing_key
}

moved {
  from = aws_cloudfront_cache_policy.web
  to   = module.hide.aws_cloudfront_cache_policy.web
}

moved {
  from = aws_cloudfront_response_headers_policy.web
  to   = module.hide.aws_cloudfront_response_headers_policy.web
}

moved {
  from = aws_cognito_user_pool.main
  to   = module.hide.aws_cognito_user_pool.main
}

moved {
  from = aws_cognito_user_pool_client.web
  to   = module.hide.aws_cognito_user_pool_client.web
}

moved {
  from = aws_cognito_user.admin
  to   = module.hide.aws_cognito_user.admin
}

moved {
  from = aws_dynamodb_table.relay
  to   = module.hide.aws_dynamodb_table.relay
}

moved {
  from = aws_iam_role.relay
  to   = module.hide.aws_iam_role.relay
}

moved {
  from = aws_iam_role_policy.relay
  to   = module.hide.aws_iam_role_policy.relay
}

moved {
  from = aws_cloudwatch_log_group.relay
  to   = module.hide.aws_cloudwatch_log_group.relay
}

moved {
  from = aws_lambda_layer_version.cryptography
  to   = module.hide.aws_lambda_layer_version.cryptography
}

moved {
  from = aws_lambda_function.relay
  to   = module.hide.aws_lambda_function.relay
}

moved {
  from = aws_lambda_function_event_invoke_config.relay
  to   = module.hide.aws_lambda_function_event_invoke_config.relay
}

moved {
  from = aws_lambda_permission.ses
  to   = module.hide.aws_lambda_permission.ses
}

moved {
  from = random_password.pgp
  to   = module.hide.random_password.pgp
}

moved {
  from = aws_ssm_parameter.pgp_secret
  to   = module.hide.aws_ssm_parameter.pgp_secret
}

moved {
  from = aws_ssm_parameter.admin_password
  to   = module.hide.aws_ssm_parameter.admin_password
}

moved {
  from = aws_cloudwatch_log_group.reset
  to   = module.hide.aws_cloudwatch_log_group.reset
}

moved {
  from = aws_iam_role.reset
  to   = module.hide.aws_iam_role.reset
}

moved {
  from = aws_iam_role_policy.reset
  to   = module.hide.aws_iam_role_policy.reset
}

moved {
  from = aws_lambda_function.reset
  to   = module.hide.aws_lambda_function.reset
}

moved {
  from = aws_cloudwatch_event_rule.reset
  to   = module.hide.aws_cloudwatch_event_rule.reset
}

moved {
  from = aws_cloudwatch_event_target.reset
  to   = module.hide.aws_cloudwatch_event_target.reset
}

moved {
  from = aws_lambda_permission.reset
  to   = module.hide.aws_lambda_permission.reset
}

moved {
  from = aws_lambda_invocation.first_reset
  to   = module.hide.aws_lambda_invocation.first_reset
}

moved {
  from = aws_s3_bucket.mail
  to   = module.hide.aws_s3_bucket.mail
}

moved {
  from = aws_s3_bucket_public_access_block.mail
  to   = module.hide.aws_s3_bucket_public_access_block.mail
}

moved {
  from = aws_s3_bucket_ownership_controls.mail
  to   = module.hide.aws_s3_bucket_ownership_controls.mail
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.mail
  to   = module.hide.aws_s3_bucket_server_side_encryption_configuration.mail
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.mail
  to   = module.hide.aws_s3_bucket_lifecycle_configuration.mail
}

moved {
  from = aws_s3_bucket_policy.mail
  to   = module.hide.aws_s3_bucket_policy.mail
}

moved {
  from = aws_sesv2_email_identity.domain
  to   = module.hide.aws_sesv2_email_identity.domain
}

moved {
  from = aws_sesv2_email_identity_mail_from_attributes.domain
  to   = module.hide.aws_sesv2_email_identity_mail_from_attributes.domain
}

moved {
  from = aws_route53_record.mail
  to   = module.hide.aws_route53_record.mail
}

moved {
  from = aws_sesv2_email_identity.forward_to
  to   = module.hide.aws_sesv2_email_identity.forward_to
}

moved {
  from = aws_ses_receipt_rule_set.main
  to   = module.hide.aws_ses_receipt_rule_set.main
}

moved {
  from = aws_ses_active_receipt_rule_set.main
  to   = module.hide.aws_ses_active_receipt_rule_set.main
}

moved {
  from = aws_ses_receipt_rule.relay
  to   = module.hide.aws_ses_receipt_rule.relay
}

moved {
  from = aws_s3_bucket.web
  to   = module.hide.aws_s3_bucket.web
}

moved {
  from = aws_s3_bucket_public_access_block.web
  to   = module.hide.aws_s3_bucket_public_access_block.web
}

moved {
  from = aws_s3_bucket_ownership_controls.web
  to   = module.hide.aws_s3_bucket_ownership_controls.web
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.web
  to   = module.hide.aws_s3_bucket_server_side_encryption_configuration.web
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.web
  to   = module.hide.aws_s3_bucket_lifecycle_configuration.web
}

moved {
  from = aws_s3_bucket_policy.web
  to   = module.hide.aws_s3_bucket_policy.web
}

moved {
  from = aws_s3_object.web
  to   = module.hide.aws_s3_object.web
}

moved {
  from = aws_s3_object.config
  to   = module.hide.aws_s3_object.config
}

moved {
  from = module.site
  to   = module.hide.module.site
}
