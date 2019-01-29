package cachememdb

import (
	"errors"
	"fmt"

	memdb "github.com/hashicorp/go-memdb"
)

const (
	tableNameIndexer = "indexer"
)

// CacheMemDB is the underlying cache database for storing indexes.
type CacheMemDB struct {
	db *memdb.MemDB
}

// New creates a new instance of CacheMemDB.
func New() (*CacheMemDB, error) {
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
					IndexNameID.String(): &memdb.IndexSchema{
						Name:   IndexNameID.String(),
						Unique: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "ID",
						},
					},
					IndexNameToken.String(): &memdb.IndexSchema{
						Name:   IndexNameToken.String(),
						Unique: false,
						Indexer: &memdb.StringFieldIndex{
							Field: "Token",
						},
					},
					IndexNameTokenAccessor.String(): &memdb.IndexSchema{
						Name:         IndexNameTokenAccessor.String(),
						Unique:       false,
						AllowMissing: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "TokenAccessor",
						},
					},
					IndexNameRequestPath.String(): &memdb.IndexSchema{
						Name:   IndexNameRequestPath.String(),
						Unique: false,
						Indexer: &memdb.StringFieldIndex{
							Field: "RequestPath",
						},
					},
					IndexNameLease.String(): &memdb.IndexSchema{
						Name:         IndexNameLease.String(),
						Unique:       true,
						AllowMissing: true,
						Indexer: &memdb.StringFieldIndex{
							Field: "Lease",
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

// GetByPrefix returns all the cached indexes based on the index name and the
// value prefix.
func (c *CacheMemDB) GetByPrefix(indexName, prefix string) ([]*Index, error) {
	indexName = indexName + "_prefix"

	txn := c.db.Txn(false)
	defer txn.Abort()

	// Get all the objects
	iter, err := txn.Get(tableNameIndexer, indexName, prefix)
	if err != nil {
		return nil, err
	}

	var indexes []*Index
	for {
		obj := iter.Next()
		if obj == nil {
			break
		}
		index, ok := obj.(*Index)
		if !ok {
			return nil, fmt.Errorf("failed to cast cached object")
		}

		indexes = append(indexes, index)
	}

	return indexes, nil
}

func (c *CacheMemDB) Get(indexName, indexValue string) (*Index, error) {
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
func (c *CacheMemDB) Evict(indexName, indexValue string) error {
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

	_, err := txn.DeleteAll(tableNameIndexer, indexName, indexValue)
	if err != nil {
		return err
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
