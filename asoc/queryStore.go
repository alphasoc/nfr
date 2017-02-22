package asoc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"strings"
	"time"
)

const (
	prefix = "namescore_queries_"
)

// QueryStore stores and saves queries to files.
type QueryStore struct {
	limit int
	dir   string
}

// NewQueryStore handles saving and reading queries from file.
func NewQueryStore(limit int, dir string) *QueryStore {
	return &QueryStore{dir: dir, limit: limit}
}

// GetQueryFiles scans directory for queries.
// If no queries are found this function returns nil.
// In case if queries are found sorted slice with absolute
// paths is returned.
func (q *QueryStore) GetQueryFiles() ([]string, error) {
	files, err := ioutil.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	var queries []string
	for _, file := range files {
		if strings.HasPrefix(file.Name(), prefix) {
			queries = append(queries, q.dir+"/"+file.Name())
		}
	}
	return queries, nil
}

// Store saves queries to local file.
// Before storing queries are decoded to JSON format.
func (q *QueryStore) Store(queries *QueriesReq) error {
	query, err := q.GetQueryFiles()
	if err != nil {
		return err
	}
	if len(query) > q.limit {
		return fmt.Errorf("quota exceeded")
	}

	payload, errjson := json.Marshal(queries)
	if errjson != nil {
		return nil
	}
	return ioutil.WriteFile(q.GenerateName(), payload, 0660)
}

// Read reads known file with queries.
func (q *QueryStore) Read(path string) (*QueriesReq, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	queries := &QueriesReq{}
	if err := json.Unmarshal(data, queries); err != nil {
		return nil, err
	}
	return queries, nil
}

// GenerateName creates unique name for query file.
func (q *QueryStore) GenerateName() string {
	return fmt.Sprintf("%s/%s%d", q.dir, prefix, time.Now().UnixNano())
}
