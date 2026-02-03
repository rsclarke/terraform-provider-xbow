# Configure the XBOW provider
provider "xbow" {
  # API key for authentication (can also use XBOW_API_KEY env var)
  api_key = var.xbow_api_key

  # Optional: Override the base URL (can also use XBOW_BASE_URL env var)
  # base_url = "https://api.xbow.example.com"
}

variable "xbow_api_key" {
  type        = string
  sensitive   = true
  description = "XBOW API key for authentication"
}
