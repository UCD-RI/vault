package cachememdb

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-test/deep"
)

func testContextInfo() *ContextInfo {
	ctx, cancelFunc := context.WithCancel(context.Background())

	return &ContextInfo{
		Ctx:        ctx,
		CancelFunc: cancelFunc,
	}
}

func TestNewCacheMemDB(t *testing.T) {
	_, err := NewCacheMemDB()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCacheMemDB_Get(t *testing.T) {
	cache, err := NewCacheMemDB()
	if err != nil {
		t.Fatal(err)
	}

	// Test invalid index name
	_, err = cache.Get("foo", "bar")
	if err == nil {
		t.Fatal("expected error")
	}

	// Test on empty cache
	index, err := cache.Get(IndexNameID.String(), "foo")
	if err != nil {
		t.Fatal(err)
	}
	if index != nil {
		t.Fatalf("expected nil index, got: %v", index)
	}

	// Populate cache
	in := &Index{
		ID:          "foo",
		TokenID:     "bar",
		LeaseID:     "baz",
		RequestPath: "/v1/request/path",
		Response:    []byte("hello world"),
	}

	if err := cache.Set(in); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name   string
		iName  string
		iValue string
	}{
		{
			"by_index_id",
			"id",
			in.ID,
		},
		{
			"by_lease_id",
			"lease_id",
			in.LeaseID,
		},
		{
			"by_token_id",
			"token_id",
			in.TokenID,
		},
		{
			"by_request_path",
			"request_path",
			in.RequestPath,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := cache.Get(tc.iName, tc.iValue)
			if err != nil {
				t.Fatal(err)
			}
			if diff := deep.Equal(in, out); diff != nil {
				t.Fatal(diff)
			}
		})
	}
}

func TestCacheMemDB_Set(t *testing.T) {
	cache, err := NewCacheMemDB()
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name    string
		index   *Index
		wantErr bool
	}{
		{
			"nil",
			nil,
			true,
		},
		{
			"empty_fields",
			&Index{},
			true,
		},
		{
			"missing_required_fields",
			&Index{
				LeaseID: "foo",
			},
			true,
		},
		{
			"all_fields",
			&Index{
				ID:           "foo",
				TokenID:      "bar",
				LeaseID:      "baz",
				RequestPath:  "/v1/request/path",
				RenewCtxInfo: testContextInfo(),
			},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := cache.Set(tc.index); (err != nil) != tc.wantErr {
				t.Fatalf("CacheMemDB.Set() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestCacheMemDB_Evict(t *testing.T) {
	cache, err := NewCacheMemDB()
	if err != nil {
		t.Fatal(err)
	}

	// Test on empty cache
	if err := cache.Evict(IndexNameID.String(), "foo"); err != nil {
		t.Fatal(err)
	}

	testIndex := &Index{
		ID:           "foo",
		TokenID:      "bar",
		LeaseID:      "baz",
		RequestPath:  "/v1/request/path",
		RenewCtxInfo: testContextInfo(),
	}

	testCases := []struct {
		name        string
		indexName   string
		indexValue  string
		insertIndex *Index
		wantErr     bool
	}{
		{
			"empty_params",
			"",
			"",
			nil,
			true,
		},
		{
			"invalid_params",
			"foo",
			"bar",
			nil,
			true,
		},
		{
			"by_index_id",
			"id",
			"foo",
			testIndex,
			false,
		},
		{
			"by_token_id",
			"token_id",
			"bar",
			testIndex,
			false,
		},
		{
			"by_lease_id",
			"id",
			"baz",
			testIndex,
			false,
		},
		{
			"by_request_path",
			"request_path",
			"/v1/request/path",
			testIndex,
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.insertIndex != nil {
				if err := cache.Set(tc.insertIndex); err != nil {
					t.Fatal(err)
				}
			}

			if err := cache.Evict(tc.indexName, tc.indexValue); (err != nil) != tc.wantErr {
				t.Fatal(err)
			}
		})
	}
}

func TestCacheMemDB_EvictAll(t *testing.T) {
	cache, err := NewCacheMemDB()
	if err != nil {
		t.Fatal(err)
	}

	// Test on empty cache
	if err := cache.EvictAll(IndexNameID.String(), "foo"); err != nil {
		t.Fatal(err)
	}

	testTokenIDIndexes := []*Index{
		&Index{
			ID:           "key1",
			TokenID:      "bar",
			LeaseID:      "lease1",
			RequestPath:  "/v1/request/path/1",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "key2",
			TokenID:      "bar",
			LeaseID:      "lease2",
			RequestPath:  "/v1/request/path/2",
			RenewCtxInfo: testContextInfo(),
		},
	}

	testReqPathIndexes := []*Index{
		&Index{
			ID:           "key1",
			TokenID:      "token1",
			LeaseID:      "lease1",
			RequestPath:  "/v1/request/path",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "key2",
			TokenID:      "token2",
			LeaseID:      "lease2",
			RequestPath:  "/v1/request/path",
			RenewCtxInfo: testContextInfo(),
		},
	}

	testCases := []struct {
		name        string
		indexName   string
		indexValue  string
		insertIndex []*Index
		wantErr     bool
	}{
		{
			"empty_params",
			"",
			"",
			nil,
			true,
		},
		{
			"invalid_params",
			"foo",
			"bar",
			nil,
			true,
		},
		{
			"by_token_id",
			"token_id",
			"bar",
			testTokenIDIndexes,
			false,
		},
		{
			"by_request_path",
			"request_path",
			"/v1/request/path",
			testReqPathIndexes,
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.insertIndex != nil {
				for _, index := range tc.insertIndex {
					if err := cache.Set(index); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := cache.EvictAll(tc.indexName, tc.indexValue); (err != nil) != tc.wantErr {
				t.Fatal(err)
			}
			if tc.wantErr {
				return
			}

			// Check that indexes are no longer in the cache
			index, err := cache.Get(tc.indexName, tc.indexValue)
			if err != nil {
				t.Fatal(err)
			}
			if index != nil {
				t.Fatalf("expected nil index after eviction, got = %v", index)
			}
		})
	}
}

func TestCacheMemDB_EvictByPrefix(t *testing.T) {
	cache, err := NewCacheMemDB()
	if err != nil {
		t.Fatal(err)
	}

	// Test on empty cache
	if err := cache.EvictAll(IndexNameID.String(), "foo"); err != nil {
		t.Fatal(err)
	}

	testLeaseIDIndexes := []*Index{
		&Index{
			ID:           "key1",
			TokenID:      "token2",
			LeaseID:      "baz/1",
			RequestPath:  "/v1/request/path",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "key2",
			TokenID:      "token2",
			LeaseID:      "baz/2",
			RequestPath:  "/v1/request/path",
			RenewCtxInfo: testContextInfo(),
		},
	}

	testReqPathIndexes := []*Index{
		&Index{
			ID:           "key1",
			TokenID:      "token1",
			LeaseID:      "lease1",
			RequestPath:  "/v1/request/path/1",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "key2",
			TokenID:      "token2",
			LeaseID:      "lease2",
			RequestPath:  "/v1/request/path/2",
			RenewCtxInfo: testContextInfo(),
		},
	}

	testCases := []struct {
		name        string
		indexName   string
		indexValue  string
		insertIndex []*Index
		wantErr     bool
	}{
		{
			"empty_params",
			"",
			"",
			nil,
			true,
		},
		{
			"invalid_params",
			"foo",
			"bar",
			nil,
			true,
		},
		{
			"by_lease_id",
			"lease_id",
			"baz",
			testLeaseIDIndexes,
			false,
		},
		{
			"by_request_path",
			"request_path",
			"/v1/request/path",
			testReqPathIndexes,
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.insertIndex != nil {
				for _, index := range tc.insertIndex {
					if err := cache.Set(index); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := cache.EvictByPrefix(tc.indexName, tc.indexValue); (err != nil) != tc.wantErr {
				t.Fatal(err)
			}
			if tc.wantErr {
				return
			}

			// Check that indexes are no longer in the cache
			foundIndexes := []*Index{}
			for i := range tc.insertIndex {
				out, err := cache.Get(IndexNameID.String(), fmt.Sprintf("key%d", i+1))
				if err != nil {
					t.Fatal(err)
				}
				if out != nil {
					foundIndexes = append(foundIndexes, out)
				}
			}
			if len(foundIndexes) != 0 {
				t.Fatalf("expected 0 matching indexes, got = %#v", foundIndexes)
			}
		})
	}
}

func TestCacheMemDB_Flush(t *testing.T) {
	cache, err := NewCacheMemDB()
	if err != nil {
		t.Fatal(err)
	}

	// Populate cache
	in := &Index{
		ID:          "foo",
		TokenID:     "bar",
		LeaseID:     "baz",
		RequestPath: "/v1/request/path",
		Response:    []byte("hello world"),
	}

	if err := cache.Set(in); err != nil {
		t.Fatal(err)
	}

	// Reset the cache
	if err := cache.Flush(); err != nil {
		t.Fatal(err)
	}

	// Check the cache doesn't contain inserted index
	out, err := cache.Get(IndexNameID.String(), "foo")
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("expected cache to be empty, got = %v", out)
	}
}
