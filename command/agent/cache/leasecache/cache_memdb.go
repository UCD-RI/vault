package leasecache

import (
	"errors"
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
)

// CacheMemDB is an implementation of the `Cache` interface using the
// hashicorp/go-memdb library.
type CacheMemDB struct {
	db *memdb.MemDB
}

func NewCacheMemDB() (Cache, error) {
	db, err := newDB()
	if err != nil {
		return nil, err
	}

	return &CacheMemDB{
		db: db,
	}, nil
}

func newDB() (*memdb.MemDB, error) {
	cacheSchema := &memdb.DBSchema{
		Tables: map[string]*memdb.TableSchema{
			"indexer": &memdb.TableSchema{
				Name: "indexer",
				Indexes: map[string]*memdb.IndexSchema{
					"id": &memdb.IndexSchema{
						Name:   "id",
						Unique: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "CacheKey",
						},
					},
					"token_id": &memdb.IndexSchema{
						Name:   "token_id",
						Unique: false,
						Indexer: &memdb.StringFieldIndex{
							Field: "TokenID",
						},
					},
					"request_path": &memdb.IndexSchema{
						Name:   "request_path",
						Unique: false,
						Indexer: &memdb.StringFieldIndex{
							Field: "RequestPath",
						},
					},
					"lease_id": &memdb.IndexSchema{
						Name:         "lease_id",
						Unique:       true,
						AllowMissing: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "LeaseID",
						},
					},
				},
			},
		},
	}

	db, err := memdb.NewMemDB(cacheSchema)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (c *CacheMemDB) Get(iName string, indexValue string) (*Index, error) {
	in := indexName(iName)
	if in == IndexNameInvalid {
		return nil, fmt.Errorf("invalid index name %q", iName)
	}
	if in == IndexNameCacheKey {
		iName = "id"
	}

	txn := c.db.Txn(false)
	defer txn.Abort()

	raw, err := txn.First("indexer", iName, indexValue)
	if err != nil {
		return nil, err
	}

	if raw == nil {
		return nil, nil
	}

	index, ok := raw.(*Index)
	if !ok {
		return nil, errors.New("unable to parse index value from the cache")
	}

	return index, nil
}

func (c *CacheMemDB) Set(index *Index) error {
	txn := c.db.Txn(true)
	defer txn.Abort()

	if err := txn.Insert("indexer", index); err != nil {
		return fmt.Errorf("unable to insert index into cache: %v", err)
	}

	txn.Commit()

	return nil
}

func (c *CacheMemDB) Evict(iName string, indexValue string) error {
	// If the iName is "cache_key", do the lookup as "id"
	if indexName(iName) == IndexNameCacheKey {
		iName = "id"
	}

	index, err := c.Get(iName, indexValue)
	if err != nil {
		return fmt.Errorf("unable to fetch index on cache deletion: %v", err)
	}

	if index == nil {
		return nil
	}

	txn := c.db.Txn(true)
	defer txn.Abort()

	if err := txn.Delete("indexer", index); err != nil {
		return fmt.Errorf("unable to delete index from cache: %v", err)
	}

	txn.Commit()

	return nil
}

func (c *CacheMemDB) EvictAll(iName, indexValue string) error {
	return c.batchEvict(iName, indexValue)
}

func (c *CacheMemDB) EvictByPrefix(iName, indexPrefix string) error {
	lookupPrefix := indexPrefix + "_prefix"
	return c.batchEvict(iName, lookupPrefix)
}

func (c *CacheMemDB) batchEvict(name, value string) error {
	txn := c.db.Txn(true)
	defer txn.Abort()

	_, err := txn.DeleteAll("indexer", name, value)
	if err != nil {
		return fmt.Errorf("unable to delete cache indexes: %v", err)
	}

	txn.Commit()

	return nil
}

func (c *CacheMemDB) Flush() error {
	newDB, err := newDB()
	if err != nil {
		return err
	}
	c.db = newDB
	return nil
}
