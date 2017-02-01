package AlphaSocAPI

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

func payloadToError(payload []byte) error {
	errResp := errorResponse{}
	if err := json.Unmarshal(payload, &errResp); err != nil {
		return err
	}

	return errors.New(errResp.Message)
}
