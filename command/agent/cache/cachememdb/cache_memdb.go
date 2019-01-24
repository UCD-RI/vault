package cachememdb

import (
	"errors"
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
)

const (
	tableNameIndexer = "indexer"
)

type CacheMemDB struct {
	db *memdb.MemDB
}

// NewCacheMemDB creates a new instance of CacheMemDB.
func NewCacheMemDB() (*CacheMemDB, error) {
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
			tableNameIndexer: &memdb.TableSchema{
				Name: tableNameIndexer,
				Indexes: map[string]*memdb.IndexSchema{
					"id": &memdb.IndexSchema{
						Name:   "id",
						Unique: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "ID",
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

// Get returns the cached index based on the index name and value.
func (c *CacheMemDB) Get(indexName string, indexValue string) (*Index, error) {
	in := indexNameFromString(indexName)
	if in == IndexNameInvalid {
		return nil, fmt.Errorf("invalid index name %q", indexName)
	}

	txn := c.db.Txn(false)
	defer txn.Abort()

	raw, err := txn.First(tableNameIndexer, indexName, indexValue)
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

// Set stores the index into the cache.
func (c *CacheMemDB) Set(index *Index) error {
	if index == nil {
		return errors.New("nil index provided")
	}

	txn := c.db.Txn(true)
	defer txn.Abort()

	if err := txn.Insert(tableNameIndexer, index); err != nil {
		return fmt.Errorf("unable to insert index into cache: %v", err)
	}

	txn.Commit()

	return nil
}

// Evict removes an index from the cache based on index name and value.
func (c *CacheMemDB) Evict(indexName string, indexValue string) error {
	index, err := c.Get(indexName, indexValue)
	if err != nil {
		return fmt.Errorf("unable to fetch index on cache deletion: %v", err)
	}

	if index == nil {
		return nil
	}

	txn := c.db.Txn(true)
	defer txn.Abort()

	if err := txn.Delete(tableNameIndexer, index); err != nil {
		return fmt.Errorf("unable to delete index from cache: %v", err)
	}

	index.RenewCtxInfo.CancelFunc()

	txn.Commit()

	return nil
}

// EvictAll removes all matching indexes from the cache based on index name and value.
func (c *CacheMemDB) EvictAll(indexName, indexValue string) error {
	return c.batchEvict(indexName, indexValue, false)
}

// EvictByPrefix removes all matching prefix indexes from the cache based on index name and prefix.
func (c *CacheMemDB) EvictByPrefix(indexName, indexPrefix string) error {
	return c.batchEvict(indexName, indexPrefix, true)
}

func (c *CacheMemDB) batchEvict(indexName, indexValue string, isPrefix bool) error {
	if isPrefix {
		indexName = indexName + "_prefix"
	}

	txn := c.db.Txn(true)
	defer txn.Abort()

	iter, err := txn.Get(tableNameIndexer, indexName, indexValue)
	if err != nil {
		return err
	}

	var objs []interface{}
	for {
		obj := iter.Next()
		if obj == nil {
			break
		}

		objs = append(objs, obj)
	}

	for _, obj := range objs {
		if err := txn.Delete(tableNameIndexer, obj); err != nil {
			return err
		}
		index, ok := obj.(*Index)
		if !ok {
			return errors.New("unable to parse index value from the cache")
		}
		index.RenewCtxInfo.CancelFunc()
	}

	txn.Commit()

	return nil
}

// Flush resets the underlying cache object.
func (c *CacheMemDB) Flush() error {
	newDB, err := newDB()
	if err != nil {
		return err
	}
	c.db = newDB
	return nil
}
