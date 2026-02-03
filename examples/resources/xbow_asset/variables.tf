variable "admin_password" {
  type        = string
  sensitive   = true
  description = "Password for admin user credential"
}

variable "mfa_password" {
  type        = string
  sensitive   = true
  description = "Password for MFA user credential"
}

variable "totp_uri" {
  type        = string
  sensitive   = true
  description = "TOTP authenticator URI for MFA"
}

variable "api_token" {
  type        = string
  sensitive   = true
  description = "API token for Authorization header"
}

variable "test_password" {
  type        = string
  sensitive   = true
  description = "Password for test user credential"
}
