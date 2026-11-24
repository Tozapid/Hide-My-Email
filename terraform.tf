terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = "~> 6.0"
      configuration_aliases = [aws.global]
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
