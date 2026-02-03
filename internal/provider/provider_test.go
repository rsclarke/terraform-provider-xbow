// Copyright IBM Corp. 2021, 2025
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
)

// testAccProtoV6ProviderFactories is used to instantiate a provider during acceptance testing.
// The factory function is called for each Terraform CLI command to create a provider
// server that the CLI can connect to and interact with.
var _ = map[string]func() (tfprotov6.ProviderServer, error){
	"xbow": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccProtoV6ProviderFactoriesWithEcho includes the echo provider alongside the xbow provider.
// It allows for testing assertions on data returned by an ephemeral resource during Open.
// The echoprovider is used to arrange tests by echoing ephemeral data into the Terraform state.
// This lets the data be referenced in test assertions with state checks.
var _ = map[string]func() (tfprotov6.ProviderServer, error){
	"xbow": providerserver.NewProtocol6WithError(New("test")()),
	"echo": echoprovider.NewProviderServer(),
}

func init() {
	_ = func(t *testing.T) {
		if os.Getenv("XBOW_API_KEY") == "" {
			t.Fatal("XBOW_API_KEY must be set for acceptance tests")
		}
	}
}
