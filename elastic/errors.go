package elastic

import (
	"errors"
	"fmt"
	"io"

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

	// read body and return as error
	errMsg := make([]byte, 1024)
	errMsgSize, _ := io.ReadFull(res.Body, errMsg)
	return fmt.Errorf("[%s] %s", res.Status(), errMsg[:errMsgSize])
}
