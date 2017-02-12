package asoc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type errorResponse struct {
	Message string `json:"message"`
}

type keyReqResp struct {
	Key string `json:"key"`
}

type StatusMsg struct {
	Level int    `json:"level"`
	Body  string `json:"body"`
}

type StatusResp struct {
	Registered bool        `json:"registered"`
	Expired    bool        `json:"expired"`
	Messages   []StatusMsg `json:"messages"`
}

type EventDetail struct {
	Type    string   `json:"type"`
	Ts      []string `json:"ts"`
	IP      string   `json:"ip"`
	QType   string   `json:"record_type"`
	FQDN    string   `json:"fqdn"`
	Risk    int      `json:"risk"`
	Flags   []string `json:"flags"`
	Threats []string `json:"threats"`
}

type ThreatInfo struct {
	Title      string `json:"title"`
	Severity   int    `json:"severity"`
	Policy     bool   `json:"policy"`
	Deprecated bool   `json:"deprecated"`
}

type EventsResp struct {
	Follow  string                `json:"follow"`
	More    bool                  `json:"more"`
	Events  []EventDetail         `json:"events"`
	Threats map[string]ThreatInfo `json:"threats"`
}

type RejectedResp struct {
	BadNames       int `json:"bad_names"`
	IgnoredDomains int `json:"ignored_domains"`
	Duplicates     int `json:"duplicates"`
}

type QueriesResp struct {
	Received int          `json:"received"`
	Accepted int          `json:"accepted"`
	Rejected RejectedResp `json:"rejected"`
}

// Strings returns events in format as following:
// timestamp;ip;record_type;domain;severity;threat_definition;flags
func (e *EventsResp) Strings() []string {
	var lines []string

	for _, event := range e.Events {
		for _, t := range event.Ts {

			var defs []string
			for _, d := range event.Threats {
				defs = append(defs, e.Threats[d].Title)
			}

			f := fmt.Sprintf("%s;%s;%s;%s;%d;%s;%s",
				t, event.IP, event.QType, event.FQDN, event.Risk, strings.Join(defs, ","), strings.Join(event.Flags, ","))

			lines = append(lines, f)
		}
	}

	return lines
}

func payloadToError(payload []byte) error {
	errResp := errorResponse{}
	if err := json.Unmarshal(payload, &errResp); err != nil {
		return err
	}

	return errors.New(errResp.Message)
}
