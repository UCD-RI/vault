package cache

import (
	"fmt"
	"os"
	"testing"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/helper/namespace"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
)

func TestCache_APIProxy(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)

	client := cores[0].Client

	defer os.Setenv(api.EnvVaultAddress, os.Getenv(api.EnvVaultAddress))
	os.Setenv(api.EnvVaultAddress, client.Address())

	defer os.Setenv(api.EnvVaultCACert, os.Getenv(api.EnvVaultCACert))
	os.Setenv(api.EnvVaultCACert, fmt.Sprintf("%s/ca_cert.pem", cluster.TempDir))

	proxier := NewAPIProxy(&APIProxyConfig{
		Logger: logging.NewVaultLogger(hclog.Trace),
	})

	r := client.NewRequest("GET", "/v1/sys/health")
	req, err := r.ToRetryableHTTP()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := proxier.Send(namespace.RootContext(nil), &SendRequest{
		Request: req.Request,
	})
	if err != nil {
		t.Fatal(err)
	}

	var result api.HealthResponse
	err = jsonutil.DecodeJSONFromReader(resp.Response.Body, &result)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Initialized || result.Sealed || result.Standby {
		t.Fatalf("bad sys/health response")
	}
}
