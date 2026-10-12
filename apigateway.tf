resource "aws_apigatewayv2_api" "http" {
  name          = local.name
  protocol_type = "HTTP"
  description   = "API of the Hide My Email page, behind the Cognito sign-in."
}

resource "aws_apigatewayv2_authorizer" "cognito" {
  api_id           = aws_apigatewayv2_api.http.id
  authorizer_type  = "JWT"
  identity_sources = ["$request.header.Authorization"]
  name             = "cognito"

  jwt_configuration {
    audience = [aws_cognito_user_pool_client.web.id]
    issuer   = "https://cognito-idp.${var.region}.amazonaws.com/${aws_cognito_user_pool.main.id}"
  }
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.http.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.relay.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "api" {
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "ANY /api/{proxy+}"
  authorization_type = "JWT"
  authorizer_id      = aws_apigatewayv2_authorizer.cognito.id
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

# The addy.io API for Bitwarden's generator: no Cognito token, an API key made
# on the page instead, which the function checks. API Gateway picks this route
# over /api/{proxy+} for /api/v1/... as the more specific one.
resource "aws_apigatewayv2_route" "public" {
  #checkov:skip=CKV_AWS_309:Callers bring an API key, not a Cognito token; the function rejects a request without a valid key.
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "ANY /api/v1/{proxy+}"
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

# The Web Key Directory: public keys, for anyone. The function answers only
# /.well-known/openpgpkey/policy and the keys of the aliases.
resource "aws_apigatewayv2_route" "web_key_directory" {
  #checkov:skip=CKV_AWS_309:Public keys are public; the Web Key Directory is read without credentials.
  count              = var.pgp_enabled ? 1 : 0
  api_id             = aws_apigatewayv2_api.http.id
  route_key          = "GET /.well-known/openpgpkey/{proxy+}"
  authorization_type = "NONE"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_cloudwatch_log_group" "api" {
  #checkov:skip=CKV_AWS_158:CloudWatch's own encryption is enough for these logs. A customer managed key would add a monthly charge.
  #checkov:skip=CKV_AWS_338:Thirty days is enough for this private page and keeps the log bill small.
  name              = "/aws/apigateway/${local.name}"
  retention_in_days = 30
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.http.id
  name        = "$default"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format = jsonencode({
      requestId = "$context.requestId"
      ip        = "$context.identity.sourceIp"
      routeKey  = "$context.routeKey"
      status    = "$context.status"
      error     = "$context.authorizer.error"
    })
  }

  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }

  depends_on = [aws_apigatewayv2_route.api, aws_apigatewayv2_route.public, aws_apigatewayv2_route.web_key_directory]
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowApiGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.relay.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.http.execution_arn}/*/*"
}
