terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
      # aws.global is us-east-1, where CloudFront and its certificates live.
      configuration_aliases = [aws.global]
    }
  }
}
