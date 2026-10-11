# Production: your own domains, mail received and sent, no public sign-in and
# no hourly reset. Copy to terraform.tfvars and fill in.

name = "hide-my-email"
demo = false

domains = [
  # DNS in Route 53: the stack writes every record.
  { name = "hide.example.com", route53_zone = "example.com" },
  # DNS elsewhere (Cloudflare, ...): records to add are in the output dns_records.
  # { name = "hide.example.org" },
]

forward_to        = "you@example.com"
verify_forward_to = true # while the SES account is in the sandbox

admin_email    = "you@example.com"
admin_password = "" # Cognito mails a temporary password instead

reset_schedule = ""
max_aliases    = 0
max_tokens     = 0
