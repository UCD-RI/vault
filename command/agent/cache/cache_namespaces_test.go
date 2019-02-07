package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/go-test/deep"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
)

func TestCache_Namespaces(t *testing.T) {
	t.Parallel()
	t.Run("send", testSendNamespaces)
	t.Run("handle_cacheclear", testHandleCacheClearNamespaces)
	t.Run("eviction_on_revocation", testEvictionOnRevocationNamespaces)
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

	cleanup, clusterClient, testClient := setupClusterAndAgent(t, coreConfig)
	defer cleanup()

	// Create a namespace
	_, err := clusterClient.Logical().Write("sys/namespaces/ns1", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mount the leased KV into ns1
	clusterClient.SetNamespace("ns1/")
	err = clusterClient.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		t.Fatal(err)
	}
	clusterClient.SetNamespace("")

	// Try request using full path
	{
		// Write some random value
		_, err = clusterClient.Logical().Write("/ns1/kv/foo", map[string]interface{}{
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
		_, err = clusterClient.Logical().Write("/ns1/kv/bar", map[string]interface{}{
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
		_, err := clusterClient.Logical().Write("/ns1/kv/baz", map[string]interface{}{
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
	coreConfig := &vault.CoreConfig{
		DisableMlock: true,
		DisableCache: true,
		Logger:       hclog.NewNullLogger(),
		LogicalBackends: map[string]logical.Factory{
			"kv": vault.LeasedPassthroughBackendFactory,
		},
	}

	cleanup, clusterClient, testClient := setupClusterAndAgent(t, coreConfig)
	defer cleanup()

	// Create a namespace
	_, err := clusterClient.Logical().Write("sys/namespaces/ns1", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mount the leased KV into ns1
	clusterClient.SetNamespace("ns1/")
	err = clusterClient.Sys().Mount("kv", &api.MountInput{
		Type: "kv",
	})
	if err != nil {
		t.Fatal(err)
	}
	clusterClient.SetNamespace("")

	// Write some random value
	_, err = clusterClient.Logical().Write("/ns1/kv/foo", map[string]interface{}{
		"value": "test",
		"ttl":   "1h",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request the secret
	firstResp, err := testClient.Logical().Read("/ns1/kv/foo")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1 * time.Second)

	// Clear by request_path and namespace
	clearPath := fmt.Sprintf("/v1/agent/cache-clear")
	data := &cacheClearRequest{
		Type:      "request_path",
		Value:     "kv/foo",
		Namespace: "ns1/",
	}

	r := testClient.NewRequest("PUT", clearPath)
	if err := r.SetJSONBody(data); err != nil {
		t.Fatal(err)
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	_, err = clusterClient.RawRequestWithContext(ctx, r)
	if err != nil {
		t.Fatal(err)
	}

	secondResp, err := testClient.Logical().Read("/ns1/kv/foo")
	if err != nil {
		t.Fatal(err)
	}

	if diff := deep.Equal(firstResp, secondResp); diff == nil {
		t.Logf("response #1: %#v", firstResp)
		t.Logf("response #2: %#v", secondResp)
		t.Fatal("expected requests to be not cached")
	}
}

func testEvictionOnRevocationNamespaces(t *testing.T) {
	t.Skip("not implemented")
}
