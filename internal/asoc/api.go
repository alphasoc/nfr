package asoc

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const (
	queries  = "/v1/queries"
	events   = "/v1/events"
	status   = "/v1/account/status"
	register = "/v1/account/register"
	verify   = "/v1/account/verify/"
	request  = "/v1/key/request"
	reset    = "/v1/key/reset"
	wisdom   = "/v1/wisdom"
)

// AlphaSOCAPI defines interface for public API
type AlphaSOCAPI interface {
	KeyRequest() (string, error)
	SetKey(key string)
	AccountStatus() (*StatusResp, error)
	Register(data *RegisterReq) error
	Events(follow string) (*EventsResp, error)
	Queries(q *QueriesReq) (*QueriesResp, error)
}

// Client handles connection to AlphaSOC server.
// There should be created one client per process.
type Client struct {
	Server     string
	httpClient http.Client
	key        string
}

// KeyRequest handles /v1/key/request API call.
// On success API key is returned.
func (c *Client) KeyRequest() (string, error) {
	payload, errjson := json.Marshal(createKeyRequest())

	if errjson != nil {
		return "", errjson
	}

	response, errpost := c.httpClient.Post(c.Server+request, "application/json", bytes.NewReader(payload))
	if errpost != nil {
		return "", errpost
	}

	respBody, errread := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if errread != nil {
		return "", errread
	}

	if response.StatusCode != 200 {
		return "", payloadToError(respBody)
	}

	key := keyReqResp{}
	if err := json.Unmarshal(respBody, &key); err != nil {
		return "", err
	}

	return key.Key, nil
}

// SetKey sets API key to the Client.
// Most Client calls requires set key.
func (c *Client) SetKey(key string) {
	c.key = key
}

// AccountStatus handles /v1/account/status API call.
func (c *Client) AccountStatus() (*StatusResp, error) {
	req, errrq := http.NewRequest("GET", c.Server+status, nil)
	if errrq != nil {
		return nil, errrq
	}

	req.SetBasicAuth(c.key, "")

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return nil, errdo
	}

	respBody, errread := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if errread != nil {
		return nil, errread
	}

	if response.StatusCode != 200 {
		return nil, payloadToError(respBody)
	}

	status := StatusResp{}
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// Register handles /v1/account/register API call.
func (c *Client) Register(data *RegisterReq) error {
	payload, errjson := json.Marshal(*data)
	if errjson != nil {
		return errjson
	}

	req, errrq := http.NewRequest("POST", c.Server+register, bytes.NewReader(payload))
	if errrq != nil {
		return errrq
	}
	req.SetBasicAuth(c.key, "")

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return errdo
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		respBody, errread := ioutil.ReadAll(response.Body)
		if errread != nil {
			return errread
		}
		return payloadToError(respBody)
	}

	return nil
}

// Events handles /v1/events API call.
func (c *Client) Events(follow string) (*EventsResp, error) {
	url := c.Server + events + "?follow=" + follow

	req, errrq := http.NewRequest("GET", url, nil)
	if errrq != nil {
		return nil, errrq
	}
	req.SetBasicAuth(c.key, "")

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return nil, errdo
	}

	respBody, errread := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if errread != nil {
		return nil, errread
	}

	if response.StatusCode != 200 {
		return nil, payloadToError(respBody)
	}

	r := &EventsResp{}

	if err := json.Unmarshal(respBody, r); err != nil {
		return nil, err
	}

	return r, nil
}

// Queries handles /v1/queries API call.
func (c *Client) Queries(q *QueriesReq) (*QueriesResp, error) {
	payload, errjson := json.Marshal(q)
	if errjson != nil {
		return nil, errjson
	}

	req, errrq := http.NewRequest("POST", c.Server+queries, bytes.NewReader(payload))
	if errrq != nil {
		return nil, errrq
	}
	req.SetBasicAuth(c.key, "")

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return nil, errdo
	}
	respBody, errread := ioutil.ReadAll(response.Body)
	defer response.Body.Close()
	if errread != nil {
		return nil, errread
	}

	if response.StatusCode != 200 {
		return nil, payloadToError(respBody)
	}

	r := &QueriesResp{}

	if err := json.Unmarshal(respBody, r); err != nil {
		return nil, err
	}

	return r, nil
}

// VerifyKey check whether key meets internal requirements.
func VerifyKey(key string) bool {
	if len(key) < 15 {
		return false
	}
	return true
}
