package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/hashicorp/vault/logical"

	"github.com/go-test/deep"
	hclog "github.com/hashicorp/go-hclog"
	kv "github.com/hashicorp/vault-plugin-secrets-kv"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/logical/pki"
	"github.com/hashicorp/vault/command/agent/cache"
	"github.com/hashicorp/vault/helper/logging"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/vault"
)

func TestInteg_Cache_nonCacheable(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		LogicalBackends: map[string]logical.Factory{
			"kv": kv.Factory,
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

	// Query mounts first
	origMounts, err := testClient.Sys().ListMounts()
	if err != nil {
		t.Fatal(err)
	}

	// Mount a kv backend
	if err := testClient.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
		Options: map[string]string{
			"version": "2",
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Query mounts again
	newMounts, err := testClient.Sys().ListMounts()
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(origMounts, newMounts); diff == nil {
		t.Logf("response #1: %#v", origMounts)
		t.Logf("response #2: %#v", newMounts)
		t.Fatal("expected requests to be not cached")
	}
}

func TestInteg_Cache_AuthResponse(t *testing.T) {
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

	// Test on auth response by creating a child token
	{
		proxiedResp, err := testClient.Logical().Write("auth/token/create", map[string]interface{}{
			"policies": "default",
		})
		if err != nil {
			t.Fatal(err)
		}
		if proxiedResp.Auth == nil || proxiedResp.Auth.ClientToken == "" {
			t.Fatalf("expected a valid client token in the response, got = %#v", proxiedResp)
		}

		cachedResp, err := testClient.Logical().Write("auth/token/create", map[string]interface{}{
			"policies": "default",
		})
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

	// Test on *non-renewable* auth response by creating a child root token
	{
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
}

func TestInteg_Cache_LeaseResponse(t *testing.T) {
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		LogicalBackends: map[string]logical.Factory{
			"pki": pki.Factory,
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

	err := client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"ttl":         "40h",
		"common_name": "myvault.com",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create a cert role. We enable lease generation in order to test the cache
	_, err = client.Logical().Write("pki/roles/test", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"generate_lease":    true,
	})
	if err != nil {
		t.Fatal(err)
	}

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

	// Issue a cert generation request, make sure that the subsequent request comes from the cache
	{
		proxyResp, err := testClient.Logical().Write("pki/issue/test", map[string]interface{}{
			"common_name": "foobar",
			"ttl":         "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		cacheResp, err := testClient.Logical().Write("pki/issue/test", map[string]interface{}{
			"common_name": "foobar",
			"ttl":         "1h",
		})
		if err != nil {
			t.Fatal(err)
		}

		if diff := deep.Equal(proxyResp, cacheResp); diff != nil {
			t.Fatal(diff)
		}
	}
}
