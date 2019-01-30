package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/go-test/deep"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/logging"

	credAppRole "github.com/hashicorp/vault/builtin/credential/approle"
	"github.com/hashicorp/vault/command/agent/cache"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
)

const basicCacheConf = `
cache {
	listener "tcp" {
			address = "127.0.0.1:8300"
			tls_disable = true
	}
}
`

func TestInteg_Cache_AuthResponse(t *testing.T) {
	var err error
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		CredentialBackends: map[string]logical.Factory{
			"approle": credAppRole.Factory,
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

	// Create the API proxier
	apiProxy := cache.NewAPIProxy(&cache.APIProxyConfig{
		Logger: cacheLogger.Named("cache.apiproxy"),
	})

	// Create the lease cache proxier and set its underlying proxier to
	// the API proxier.
	leaseCache, err := cache.NewLeaseCache(&cache.LeaseCacheConfig{
		BaseContext: ctx,
		Proxier:     apiProxy,
		Logger:      cacheLogger.Named("cache.leasecache"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a muxer and add paths relevant for the lease cache layer
	mux := http.NewServeMux()
	mux.Handle("/v1/agent/cache-clear", leaseCache.HandleCacheClear(ctx))

	// Start listening to requests
	cache.Run(ctx, &cache.Config{
		Token:            client.Token(),
		Proxier:          leaseCache,
		UseAutoAuthToken: false,
		Listeners:        []net.Listener{listener},
		Handler:          mux,
		Logger:           cacheLogger.Named("cache.handler"),
	})

	// Clone a client to query from the agent's listener address
	testClient, err := client.Clone()
	if err != nil {
		t.Fatal(err)
	}

	if err := testClient.SetAddress("http://" + listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	testClient.SetToken(cluster.RootToken)

	proxiedResp, err := testClient.Logical().Write("auth/token/create", nil)
	if err != nil {
		t.Fatal(err)
	}
	if proxiedResp.Auth == nil || proxiedResp.Auth.ClientToken == "" {
		t.Fatalf("expected a valid client token in the response, got = %#v", proxiedResp)
	}

	cachedResp, err := testClient.Logical().Write("auth/token/create", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cachedResp.Auth == nil || cachedResp.Auth.ClientToken == "" {
		t.Fatalf("expected a valid client token in the response, got = %#v", cachedResp)
	}

	if diff := deep.Equal(proxiedResp.Auth.ClientToken, cachedResp.Auth.ClientToken); diff != nil {
		t.Fatal(diff)
	}
}
