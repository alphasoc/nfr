package asoc

import (
	"encoding/json"
	"errors"
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

func payloadToError(payload []byte) error {
	errResp := errorResponse{}
	if err := json.Unmarshal(payload, &errResp); err != nil {
		return err
	}

	return errors.New(errResp.Message)
}
