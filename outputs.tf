output "site_urls" {
  description = "Addresses of the page"
  value       = [for key, site in module.site : key == "default" ? "https://${site.distribution_domain_name}" : "https://${key}"]
}

output "alias_domains" {
  description = "Domains of the aliases; the first is the default"
  value       = local.alias_domains
}

output "mail" {
  description = "Whether mail is received and sent"
  value       = local.mail
}

output "user_pool_id" {
  description = "Cognito user pool of the page; more users are added there"
  value       = aws_cognito_user_pool.main.id
}

output "mail_bucket" {
  description = "S3 bucket with received messages (incoming/), the message log (messages/) and attachments (attachments/)"
  value       = aws_s3_bucket.mail.id
}

output "table_name" {
  description = "DynamoDB table with aliases, reply codes, the message log and API keys"
  value       = aws_dynamodb_table.relay.name
}

# Records to add at the DNS host of each domain without a Route 53 zone: mail,
# the certificate's validation and the site's CNAME, none of them proxied at
# a CDN. The site's CNAME shares its name with the MX record, so the DNS host
# has to flatten it (Cloudflare: CNAME flattening).
output "dns_records" {
  description = "DNS records to add by hand for each domain without route53_zone"
  value = {
    for domain in var.domains : domain.name => concat(
      [for record in local.mail_records[domain.name] : { type = record.type, name = record.name, value = record.value }],
      domain.mail_only ? [] : module.site[domain.name].certificate_validation_records,
      domain.mail_only ? [] : [{ type = "CNAME", name = domain.name, value = module.site[domain.name].distribution_domain_name }],
    ) if domain.route53_zone == null
  }
}
