variable "region" {
  type    = string
  default = "ap-southeast-2"
}
variable "admin_cidr" {
  type        = string
  description = "Administrator public IPv4 address with /32 suffix"
  validation {
    condition     = can(cidrhost(var.admin_cidr, 0)) && endswith(var.admin_cidr, "/32")
    error_message = "SSH access must be a single administrator IPv4 /32."
  }
}
variable "key_name" {
  type        = string
  description = "Existing EC2 SSH key pair name"
}
