package alerts

import (
	"github.com/alphasoc/nfr/client"
)

// Writer interface for log api alerts response.
type Writer interface {
	Write(*client.AlertsResponse) error
}
