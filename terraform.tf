terraform {
  # 1.10 brings the S3 lockfile (use_lockfile).
  required_version = ">= 1.10.0"

  # Partial configuration: bucket, key and region come from terraform init
  # (see README). The S3 lockfile replaces a DynamoDB lock table.
  backend "s3" {
    encrypt      = true
    use_lockfile = true
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
    # Runs lambda/build_layer.py while planning, for the layer of pgp.py.
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    # The secret the OpenPGP keys of the aliases come from (pgp.tf).
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
