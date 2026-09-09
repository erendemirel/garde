variable "netcup_customer_number" {
  description = "netcup customer number (CCP DNS API)"
  type        = string
}

variable "netcup_api_key" {
  description = "netcup CCP API key"
  type        = string
  sensitive   = true
}

variable "netcup_api_password" {
  description = "netcup CCP API password"
  type        = string
  sensitive   = true
}

variable "netcup_scp_refresh_token" {
  description = "netcup SCP REST API refresh token (only needed for SCP resources)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "zone" {
  description = "DNS zone, e.g. example.com. The zone must already exist; the CCP API cannot create zones."
  type        = string
}

variable "app_hostname" {
  description = "Hostname for the web UI, relative to the zone"
  type        = string
  default     = "app"
}

variable "api_hostname" {
  description = "Hostname for the garde API, relative to the zone"
  type        = string
  default     = "api"
}

variable "failover_ip" {
  description = "The netcup failover IPv4 address that both records point at"
  type        = string
}

variable "zone_ttl" {
  description = <<-EOT
    Zone TTL in seconds. netcup has no per-record TTL, so this applies to the
    whole zone. It is kept low because DNS is the fallback path if the failover
    IP ever has to be abandoned; normal failover moves the IP and never touches
    DNS at all.
  EOT
  type        = number
  default     = 300
}
