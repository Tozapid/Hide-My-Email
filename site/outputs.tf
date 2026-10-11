output "distribution_arn" {
  description = "ARN of the distribution, for the bucket policies"
  value       = aws_cloudfront_distribution.this.arn
}

output "distribution_domain_name" {
  description = "Domain of the distribution: the address of the page without a domain, or the target of the site's CNAME at an outside DNS host"
  value       = aws_cloudfront_distribution.this.domain_name
}

output "certificate_validation_records" {
  description = "Records that validate the certificate, for an outside DNS host"
  value = [
    for option in flatten(aws_acm_certificate.this[*].domain_validation_options) : {
      type  = option.resource_record_type
      name  = trimsuffix(option.resource_record_name, ".")
      value = trimsuffix(option.resource_record_value, ".")
    }
  ]
}
