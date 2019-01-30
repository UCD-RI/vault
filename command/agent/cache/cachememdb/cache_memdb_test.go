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

func TestNew(t *testing.T) {
	_, err := New()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCacheMemDB_Get(t *testing.T) {
	cache, err := New()
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
		ID:            "test_id",
		RequestPath:   "/v1/request/path",
		Token:         "test_token",
		TokenAccessor: "test_accessor",
		Lease:         "test_lease",
		Response:      []byte("hello world"),
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
			"by_request_path",
			"request_path",
			in.RequestPath,
		},
		{
			"by_lease",
			"lease",
			in.Lease,
		},
		{
			"by_token",
			"token",
			in.Token,
		},
		{
			"by_token_accessor",
			"token_accessor",
			in.TokenAccessor,
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
	cache, err := New()
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
				Lease: "foo",
			},
			true,
		},
		{
			"all_fields",
			&Index{
				ID:            "test_id",
				RequestPath:   "/v1/request/path",
				Token:         "test_token",
				TokenAccessor: "test_accessor",
				Lease:         "test_lease",
				RenewCtxInfo:  testContextInfo(),
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
	cache, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Test on empty cache
	if err := cache.Evict(IndexNameID.String(), "foo"); err != nil {
		t.Fatal(err)
	}

	testIndex := &Index{
		ID:            "test_id",
		RequestPath:   "/v1/request/path",
		Token:         "test_token",
		TokenAccessor: "test_token_accessor",
		Lease:         "test_lease",
		RenewCtxInfo:  testContextInfo(),
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
			"by_id",
			"id",
			"test_id",
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
		{
			"by_token",
			"token",
			"test_token",
			testIndex,
			false,
		},
		{
			"by_token_accessor",
			"token_accessor",
			"test_accessor",
			testIndex,
			false,
		},
		{
			"by_lease",
			"lease",
			"test_lease",
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
	cache, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Test on empty cache
	if err := cache.EvictAll(IndexNameID.String(), "foo"); err != nil {
		t.Fatal(err)
	}

	// The following set inserts indexes using the same token for
	// multi-eviction
	testTokenIndexes := []*Index{
		&Index{
			ID:           "test_id_1",
			Token:        "test_token",
			Lease:        "test_lease_1",
			RequestPath:  "/v1/request/path/1",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "test_id_2",
			Token:        "test_token",
			Lease:        "test_lease_2",
			RequestPath:  "/v1/request/path/2",
			RenewCtxInfo: testContextInfo(),
		},
	}

	// The following set inserts indexes using the same token accessor for
	// multi-eviction
	testTokenAccessorIndexes := []*Index{
		&Index{
			ID:            "test_id_1",
			Token:         "test_token",
			TokenAccessor: "test_token_accessor",
			Lease:         "test_lease_1",
			RequestPath:   "/v1/request/path/1",
			RenewCtxInfo:  testContextInfo(),
		},
		&Index{
			ID:            "test_id_2",
			Token:         "test_token",
			TokenAccessor: "test_token_accessor",
			Lease:         "test_lease_2",
			RequestPath:   "/v1/request/path/2",
			RenewCtxInfo:  testContextInfo(),
		},
	}

	// The following set inserts indexes using the same requestpath for
	// multi-eviction
	testReqPathIndexes := []*Index{
		&Index{
			ID:           "test_id_1",
			Token:        "test_token_1",
			Lease:        "test_lease_1",
			RequestPath:  "/v1/request/path",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "test_id_2",
			Token:        "test_token_2",
			Lease:        "test_lease_2",
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
			"by_token",
			"token",
			"test_token",
			testTokenIndexes,
			false,
		},
		{
			"by_token_accessor",
			"token_accessor",
			"test_token_accessor",
			testTokenAccessorIndexes,
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
	cache, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Test on empty cache
	if err := cache.EvictAll(IndexNameID.String(), "foo"); err != nil {
		t.Fatal(err)
	}

	testLeaseIndexes := []*Index{
		&Index{
			ID:           "test_id_1",
			Token:        "test_token_1",
			Lease:        "baz/1",
			RequestPath:  "/v1/request/path",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "test_id_2",
			Token:        "test_token_2",
			Lease:        "baz/2",
			RequestPath:  "/v1/request/path",
			RenewCtxInfo: testContextInfo(),
		},
	}

	testReqPathIndexes := []*Index{
		&Index{
			ID:           "test_id_1",
			Token:        "test_token_1",
			Lease:        "test_lease_1",
			RequestPath:  "/v1/request/path/1",
			RenewCtxInfo: testContextInfo(),
		},
		&Index{
			ID:           "test_id_2",
			Token:        "test_token_2",
			Lease:        "test_lease_2",
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
			"by_lease",
			"lease",
			"baz",
			testLeaseIndexes,
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
	cache, err := New()
	if err != nil {
		t.Fatal(err)
	}

	// Populate cache
	in := &Index{
		ID:          "test_id",
		Token:       "test_token",
		Lease:       "test_lease",
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
	out, err := cache.Get(IndexNameID.String(), "test_id")
	if err != nil {
		t.Fatal(err)
	}
	if out != nil {
		t.Fatalf("expected cache to be empty, got = %v", out)
	}
}
