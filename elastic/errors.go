package elastic

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// ErrQueryTimeout is returned when the search query has timed out.
var ErrQueryTimeout = errors.New("query timeout")

// IsAPIError checks if an es response contains an error.
// If so, it decodes the body and returns the error.
func IsAPIError(res *esapi.Response) error {
	if !res.IsError() {
		return nil
	}

	var e map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&e); err != nil {
		return err
	}

	return fmt.Errorf("[%s] %s: %s",
		res.Status(),
		e["error"].(map[string]interface{})["type"],
		e["error"].(map[string]interface{})["reason"])
}
