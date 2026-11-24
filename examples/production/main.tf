# Production: your own domains, mail received and sent, no public sign-in and
# no reset. Pin the module to a release tag; a newer release is a change of
# ref.
terraform {
  required_version = ">= 1.10.0"

  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# SES receives mail only in some regions, eu-central-1 among them.
provider "aws" {
  region = "eu-central-1"
}

# CloudFront and its certificates live in us-east-1.
provider "aws" {
  alias  = "global"
  region = "us-east-1"
}

module "hide" {
  source = "git::https://github.com/Tozapid/Hide-My-Email.git?ref=v1.9.1"

  providers = {
    aws        = aws
    aws.global = aws.global
  }

  name = "hide-my-email"
  domains = [
    # DNS in Route 53: the module writes every record.
    { name = "hide.example.com", route53_zone = "example.com" },
    # DNS elsewhere (Cloudflare, ...): the records to add are in the output
    # dns_records.
    # { name = "hide.example.org" },
  ]
  forward_to        = "you@example.com"
  verify_forward_to = true # while the SES account is in the sandbox
  # Cognito mails it a temporary password.
  admin_email = "you@example.com"
}

output "site_url" {
  description = "Address of the page."
  value       = module.hide.site_url
}

output "dns_records" {
  description = "DNS records to add by hand for each domain without route53_zone."
  value       = module.hide.dns_records
}
