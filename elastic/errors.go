package elastic

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elastic/go-elasticsearch/v7/esapi"
)

// ErrQueryTimeout is returned when the search query has timed out.
var ErrQueryTimeout = errors.New("query timeout")

// dumpRootCauses returns a string representation of all root_cause entries as:
//   "type1: reason1; type2: reason2; ...; typeN: reasonN"
func dumpRootCauses(rcs []interface{}) string {
	var rcsStr string
	for _, rc := range rcs {
		rcsStr += fmt.Sprintf(
			"; %s: %s",
			rc.(map[string]interface{})["type"],
			rc.(map[string]interface{})["reason"])
	}
	return rcsStr
}

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

	if e["error"].(map[string]interface{})["root_cause"] != nil {
		return fmt.Errorf("[%s] %s: %s%s",
			res.Status(),
			e["error"].(map[string]interface{})["type"],
			e["error"].(map[string]interface{})["reason"],
			dumpRootCauses(e["error"].(map[string]interface{})["root_cause"].([]interface{})))
	}
	return fmt.Errorf("[%s] %s: %s",
		res.Status(),
		e["error"].(map[string]interface{})["type"],
		e["error"].(map[string]interface{})["reason"])
}
