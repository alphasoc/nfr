package asoc

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const (
	queries   = "/v1/queries"
	events    = "/v1/events"
	status    = "/v1/account/status"
	register  = "/v1/account/register"
	request   = "/v1/key/request"
	userAgent = "AlphaSOC Namescore/0.1"
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

	req, errrq := http.NewRequest(http.MethodPost, c.Server+request, bytes.NewReader(payload))
	if errrq != nil {
		return "", errrq
	}
	req.Header.Set("User-Agent", userAgent)

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return "", errdo
	}

	respBody, errread := ioutil.ReadAll(response.Body)
	if err := response.Body.Close(); err != nil {
		return "", err
	}

	if errread != nil {
		return "", errread
	}

	if response.StatusCode != http.StatusOK {
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
	req, errrq := http.NewRequest(http.MethodGet, c.Server+status, nil)
	if errrq != nil {
		return nil, errrq
	}
	req.Header.Set("User-Agent", userAgent)
	req.SetBasicAuth(c.key, "")

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return nil, errdo
	}

	respBody, errread := ioutil.ReadAll(response.Body)

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	if errread != nil {
		return nil, errread
	}

	if response.StatusCode != http.StatusOK {
		return nil, payloadToError(respBody)
	}

	status := StatusResp{}
	if err := json.Unmarshal(respBody, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// Register handles /v1/account/register API call.
func (c *Client) Register(data *RegisterReq) (err error) {
	payload, errjson := json.Marshal(*data)
	if errjson != nil {
		return errjson
	}

	req, errrq := http.NewRequest(http.MethodPost, c.Server+register, bytes.NewReader(payload))
	if errrq != nil {
		return errrq
	}
	req.SetBasicAuth(c.key, "")
	req.Header.Set("User-Agent", userAgent)

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return errdo
	}

	defer func() {
		if errClose := response.Body.Close(); errClose != nil && err == nil {
			err = errClose
		}
	}()

	if response.StatusCode != http.StatusOK {
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

	req, errrq := http.NewRequest(http.MethodGet, url, nil)
	if errrq != nil {
		return nil, errrq
	}
	req.SetBasicAuth(c.key, "")
	req.Header.Set("User-Agent", userAgent)

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return nil, errdo
	}

	respBody, errread := ioutil.ReadAll(response.Body)
	if errread != nil {
		return nil, errread
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
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

	req, errrq := http.NewRequest(http.MethodPost, c.Server+queries, bytes.NewReader(payload))
	if errrq != nil {
		return nil, errrq
	}
	req.SetBasicAuth(c.key, "")
	req.Header.Set("User-Agent", userAgent)

	response, errdo := c.httpClient.Do(req)
	if errdo != nil {
		return nil, errdo
	}
	respBody, errread := ioutil.ReadAll(response.Body)
	if errread != nil {
		return nil, errread
	}

	if err := response.Body.Close(); err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
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
	return len(key) > 15
}
