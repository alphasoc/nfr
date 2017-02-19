package asoc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"
	"time"
)

const (
	prefix = "namescore_queries_"
)

type QueryStore struct {
	limit uint
	dir   string
}

func NewQueryStore(limit uint, dir string) *QueryStore {
	return &QueryStore{dir: dir, limit: limit}
}

func (q *QueryStore) GetQueryFiles() []string {
	files, err := ioutil.ReadDir(q.dir)
	if err != nil {
		return nil
	}
	var queries []string
	for _, file := range files {
		if strings.HasPrefix(file.Name(), prefix) {
			queries = append(queries, q.dir+"/"+file.Name())
		}
	}
	sort.Strings(queries)
	return queries
}

func (q *QueryStore) Store(queries *QueriesReq) error {
	if len(q.GetQueryFiles()) > int(q.limit) {
		return fmt.Errorf("Store: quota exceeded")
	}

	payload, errjson := json.Marshal(queries)
	if errjson != nil {
		return nil
	}
	return ioutil.WriteFile(q.GenerateName(), payload, 0660)
}

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

func (q *QueryStore) GenerateName() string {
	return fmt.Sprintf("%s/%s%d", q.dir, prefix, time.Now().UnixNano())
}
