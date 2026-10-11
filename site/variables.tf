variable "domain" {
  type        = string
  default     = null
  description = "Domain of the page; the certificate and the distribution are for it alone. Null: no certificate, the distribution answers at its *.cloudfront.net address."
}

variable "route53_zone_id" {
  type        = string
  default     = null
  description = "Route 53 zone that holds the domain. With it the module writes the certificate's validation record and the A and AAAA aliases; without it they are added at the DNS host by hand, from the outputs."
}

variable "comment" {
  type        = string
  description = "Comment of the distribution."
}

variable "origins" {
  type = object({
    web_bucket_domain  = string
    web_oac_id         = string
    mail_bucket_domain = string
    mail_oac_id        = string
    api_domain         = string
  })
  description = "Where the page, the attachments and the API come from: the regional domains of the two buckets with their origin access controls, and the execute-api domain."
}

variable "policies" {
  type = object({
    web_cache_id              = string
    response_headers_id       = string
    caching_disabled_id       = string
    all_viewer_except_host_id = string
    attachments_key_group_id  = string
  })
  description = "Shared CloudFront policies: the cache of the page, the security headers, no caching for the API and the attachments, the forwarding of viewer headers to the API, and the key group that signs the attachment cookie."
}
