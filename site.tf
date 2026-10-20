# The page: one distribution per alias domain, each with a certificate of its
# own, from the module in site/. Without domains (the demo) one distribution
# answers at its *.cloudfront.net address.
module "site" {
  source   = "./site"
  for_each = local.sites

  providers = {
    aws        = aws
    aws.global = aws.global
  }

  domain          = each.value == null ? null : each.key
  route53_zone_id = try(data.aws_route53_zone.domain[each.value.route53_zone].zone_id, null)
  comment         = each.value == null ? local.name : "${local.name} ${each.key}"

  web_key_directory = var.pgp_enabled

  access_logs_bucket = var.access_logs_bucket != "" ? var.access_logs_bucket : null
  access_logs_name   = each.value == null ? local.name : "${local.name}-${replace(each.key, ".", "-")}"

  origins = {
    web_bucket_domain  = aws_s3_bucket.web.bucket_regional_domain_name
    web_oac_id         = aws_cloudfront_origin_access_control.web.id
    mail_bucket_domain = aws_s3_bucket.mail.bucket_regional_domain_name
    mail_oac_id        = aws_cloudfront_origin_access_control.mail.id
    api_domain         = "${aws_apigatewayv2_api.http.id}.execute-api.${var.region}.amazonaws.com"
  }

  policies = {
    web_cache_id              = aws_cloudfront_cache_policy.web.id
    response_headers_id       = aws_cloudfront_response_headers_policy.web.id
    caching_disabled_id       = data.aws_cloudfront_cache_policy.caching_disabled.id
    all_viewer_except_host_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    attachments_key_group_id  = aws_cloudfront_key_group.attachments.id
  }
}
