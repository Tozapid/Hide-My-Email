variable "region" {
  type        = string
  default     = "eu-central-1"
  description = "Region of every resource but CloudFront. SES receives mail only in some regions, eu-central-1 among them."
}

variable "name" {
  type        = string
  default     = "hme-demo"
  description = "Prefix of every resource name; bucket names add the account id. The deploy role of the demo is limited to it."
}

variable "demo" {
  type        = bool
  default     = true
  description = "Public demo: the sign-in screen shows and fills in the demo sign-in, and the account settings hide the password and two-factor authentication."
}

variable "domains" {
  type = list(object({
    name         = string
    route53_zone = optional(string)
  }))
  default     = []
  description = "Alias domains; the first is the default. Each gets mail (SES receiving and sending) and the page with a certificate of its own. With route53_zone the stack writes the DNS records into that zone; without it they are in the output dns_records. Empty: no mail, the page on the CloudFront address (the demo)."
}

variable "demo_domain" {
  type        = string
  default     = "hide.example.com"
  description = "Domain the aliases show while domains is empty. Nothing is received there."
}

variable "forward_to" {
  type        = string
  default     = "you@example.com"
  description = "Personal address that receives the mail of aliases without an address of their own, and the only one allowed to reply for them."

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.forward_to))
    error_message = "forward_to has to be an email address."
  }
}

variable "verify_forward_to" {
  type        = bool
  default     = false
  description = "Make an SES identity for forward_to, so that AWS mails it a verification link. Needed while the SES account is in the sandbox; only with mail."
}

variable "admin_email" {
  type        = string
  default     = "demo@example.com"
  description = "Sign-in of the first user. Self sign-up is off; more users are added in the Cognito console."
}

variable "admin_password" {
  type        = string
  default     = "Demo-Password-1"
  sensitive   = true
  description = "Permanent password of the first user, published in the demo and put back by the reset. Empty: Cognito mails admin_email a temporary password instead."
}

variable "password_min_length" {
  type        = number
  default     = 12
  description = "Minimum password length; letters of both cases, a digit and a symbol are required too."
}

variable "reset_schedule" {
  type        = string
  default     = "rate(1 hour)"
  description = "When the demo goes back to its initial state: aliases, keys and the message log are wiped and the examples of seed/seed.json written again, the first user gets admin_password back and other users go. An empty string turns the reset off."
}

variable "max_aliases" {
  type        = number
  default     = 100
  description = "Most aliases at once; 0 for no limit. Keeps a public demo small."
}

variable "max_tokens" {
  type        = number
  default     = 20
  description = "Most API keys at once; 0 for no limit."
}

variable "max_relays" {
  type        = number
  default     = 200
  description = "Most correspondents (reply addresses) a visitor can add on the page; 0 for no limit."
}

variable "mail_retention_days" {
  type        = number
  default     = 30
  description = "Days received messages stay under incoming/. The message log is kept until it is deleted on the page."
}

variable "tags" {
  type = map(string)
  default = {
    Managed = "IAC"
    Project = "Hide-My-Email"
  }
  description = "Tags applied to supported resources."
}
