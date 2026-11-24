# The public demo: the module of this repository at its CloudFront address,
# with the sign-in published on the page, no domains (so no mail is received
# or sent), small limits and the reset six hours after a change. The CI of the repository
# deploys it from this directory.
provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

provider "aws" {
  alias  = "global"
  region = "us-east-1"

  default_tags {
    tags = var.tags
  }
}

module "hide" {
  source = "../"

  providers = {
    aws        = aws
    aws.global = aws.global
  }

  name               = var.name
  demo               = true
  forward_to         = "you@example.com"
  admin_email        = "demo@example.com"
  admin_password     = "Demo-Password-1"
  reset_delay_hours  = 6
  max_aliases        = 100
  max_tokens         = 20
  max_relays         = 200
  access_logs_bucket = var.access_logs_bucket
}
