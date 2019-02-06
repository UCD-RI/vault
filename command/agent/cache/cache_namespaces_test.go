package cache

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/go-test/deep"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
)

func TestCache_Namespaces(t *testing.T) {
	testSendNamespaces(t)
	testHandleCacheClearNamespaces(t)
	testEvictionOnRevocationNamespaces(t)
}

func testSendNamespaces(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		LogicalBackends: map[string]logical.Factory{
			"kv": vault.LeasedPassthroughBackendFactory,
		},
	}

	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	cores := cluster.Cores
	vault.TestWaitActive(t, cores[0].Core)
	client := cores[0].Client

	// Create a namespace
	_, err := client.Logical().Write("sys/namespaces/ns1", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mount the leased KV into ns1
	client.SetNamespace("ns1/")
	err = client.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetNamespace("")

	// Set up env vars for agent consumption
	defer os.Setenv(api.EnvVaultAddress, os.Getenv(api.EnvVaultAddress))
	os.Setenv(api.EnvVaultAddress, client.Address())

	defer os.Setenv(api.EnvVaultCACert, os.Getenv(api.EnvVaultCACert))
	os.Setenv(api.EnvVaultCACert, fmt.Sprintf("%s/ca_cert.pem", cluster.TempDir))

	cacheLogger := logging.NewVaultLogger(hclog.Trace)
	ctx := context.Background()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Start listening to requests
	err = Run(ctx, &Config{
		Token:            client.Token(),
		UseAutoAuthToken: false,
		Listeners:        []net.Listener{listener},
		Logger:           cacheLogger.Named("cache"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Clone a client to query from the agent's listener address
	testClient, err := client.Clone()
	if err != nil {
		t.Fatal(err)
	}

	if err := testClient.SetAddress("http://" + listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	testClient.SetToken(cluster.RootToken)

	// Try request using full path
	{
		// Write some random value
		_, err = client.Logical().Write("/ns1/kv/foo", map[string]interface{}{
			"value": "test",
			"ttl":   "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		proxiedResp, err := testClient.Logical().Read("/ns1/kv/foo")
		if err != nil {
			t.Fatal(err)
		}

		cachedResp, err := testClient.Logical().Read("/ns1/kv/foo")
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(proxiedResp, cachedResp); diff != nil {
			t.Fatal(diff)
		}
	}

	// Try request using the namespace header
	{
		// Write some random value
		_, err = client.Logical().Write("/ns1/kv/bar", map[string]interface{}{
			"value": "test",
			"ttl":   "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		testClient.SetNamespace("ns1/")
		proxiedResp, err := testClient.Logical().Read("/kv/bar")
		if err != nil {
			t.Fatal(err)
		}

		cachedResp, err := testClient.Logical().Read("/kv/bar")
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(proxiedResp, cachedResp); diff != nil {
			t.Fatal(diff)
		}

		testClient.SetNamespace("")
	}

	// Try the same request using different namespace input methods (header vs
	// full path), they should not be the same cache entry (i.e. should produce
	// different lease ID's).
	{
		_, err := client.Logical().Write("/ns1/kv/baz", map[string]interface{}{
			"value": "test",
			"ttl":   "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		proxiedResp, err := testClient.Logical().Read("/ns1/kv/baz")
		if err != nil {
			t.Fatal(err)
		}

		testClient.SetNamespace("ns1/")
		cachedResp, err := testClient.Logical().Read("/kv/baz")
		if err != nil {
			t.Fatal(err)
		}
		testClient.SetNamespace("")

		if diff := deep.Equal(proxiedResp, cachedResp); diff == nil {
			t.Logf("response #1: %#v", proxiedResp)
			t.Logf("response #2: %#v", cachedResp)
			t.Fatal("expected requests to be not cached")
		}
	}
}

func testHandleCacheClearNamespaces(t *testing.T) {
	t.Skip("not implemented")

}

func testEvictionOnRevocationNamespaces(t *testing.T) {
	t.Skip("not implemented")
}
