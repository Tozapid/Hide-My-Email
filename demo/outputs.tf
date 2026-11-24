# The CI writes site_url into the summary of a deploy and the comment of a
# preview.
output "site_url" {
  description = "Address of the page."
  value       = module.hide.site_url
}

output "site_urls" {
  description = "Addresses of the page."
  value       = module.hide.site_urls
}

output "user_pool_id" {
  description = "Cognito user pool of the page."
  value       = module.hide.user_pool_id
}
