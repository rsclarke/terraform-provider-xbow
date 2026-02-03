# Basic asset with minimal configuration
resource "xbow_asset" "basic" {
  name            = "my-web-app"
  organization_id = "org-123"
  sku             = "standard"
}

# Asset with rate limiting and start URL
resource "xbow_asset" "with_config" {
  name                    = "my-api"
  organization_id         = "org-123"
  sku                     = "enterprise"
  start_url               = "https://api.example.com"
  max_requests_per_second = 10
}

# Asset with credentials for authenticated scanning
resource "xbow_asset" "authenticated" {
  name            = "authenticated-app"
  organization_id = "org-123"
  sku             = "standard"
  start_url       = "https://app.example.com"

  credentials = [
    {
      name     = "admin-user"
      type     = "basic"
      username = "admin"
      password = var.admin_password
    },
    {
      name              = "mfa-user"
      type              = "totp"
      username          = "mfa-admin"
      password          = var.mfa_password
      email_address     = "admin@example.com"
      authenticator_uri = var.totp_uri
    }
  ]
}

# Asset with boundary rules
resource "xbow_asset" "with_boundaries" {
  name            = "scoped-app"
  organization_id = "org-123"
  sku             = "standard"
  start_url       = "https://app.example.com"

  dns_boundary_rules = [
    {
      action             = "allow-attack"
      type               = "domain"
      filter             = "example.com"
      include_subdomains = true
    },
    {
      action = "deny-attack"
      type   = "domain"
      filter = "external.com"
    }
  ]

  http_boundary_rules = [
    {
      action = "allow-attack"
      type   = "path"
      filter = "/api/*"
    },
    {
      action = "deny-attack"
      type   = "path"
      filter = "/admin/*"
    }
  ]
}

# Asset with custom headers
resource "xbow_asset" "with_headers" {
  name            = "header-app"
  organization_id = "org-123"
  sku             = "standard"
  start_url       = "https://app.example.com"

  headers = {
    "X-Custom-Header" = ["value1", "value2"]
    "Authorization"   = ["Bearer ${var.api_token}"]
  }
}

# Asset with approved time windows
resource "xbow_asset" "scheduled" {
  name            = "scheduled-app"
  organization_id = "org-123"
  sku             = "standard"
  start_url       = "https://app.example.com"

  approved_time_windows = {
    tz = "America/New_York"
    entries = [
      {
        start_weekday = 1 # Monday
        start_time    = "22:00"
        end_weekday   = 2 # Tuesday
        end_time      = "06:00"
      },
      {
        start_weekday = 5 # Friday
        start_time    = "22:00"
        end_weekday   = 0 # Sunday
        end_time      = "06:00"
      }
    ]
  }
}

# Full example with all options
resource "xbow_asset" "complete" {
  name                    = "complete-app"
  organization_id         = "org-123"
  sku                     = "enterprise"
  start_url               = "https://app.example.com"
  max_requests_per_second = 20

  credentials = [
    {
      name     = "test-user"
      type     = "basic"
      username = "tester"
      password = var.test_password
    }
  ]

  dns_boundary_rules = [
    {
      action             = "allow-attack"
      type               = "domain"
      filter             = "example.com"
      include_subdomains = true
    }
  ]

  http_boundary_rules = [
    {
      action = "allow-attack"
      type   = "path"
      filter = "/*"
    }
  ]

  headers = {
    "X-Test-Mode" = ["true"]
  }

  approved_time_windows = {
    tz = "UTC"
    entries = [
      {
        start_weekday = 6 # Saturday
        start_time    = "00:00"
        end_weekday   = 0 # Sunday
        end_time      = "23:59"
      }
    ]
  }
}
