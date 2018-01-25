package suricata

import (
	"encoding/json"
	"strings"
	"time"
)

// timestamp type to use when parse eve log entries.
type timestamp time.Time

// time format used in suricata eve logs.
const timestampFormat = "2006-01-02T15:04:05.999999999-0700"

func (t *timestamp) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), "\"")
	_t, err := time.Parse(timestampFormat, s)
	if err != nil {
		return err
	}
	*t = timestamp(_t)
	return nil

}

func (t *timestamp) MarshalJSON() ([]byte, error) {
	return json.Marshal(t)
}
