// Package asoc provides functions to handle AlphaSOC public API and manage API related files.
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
	userAgent = "AlphaSOC Namescore/"
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
	Version    string
	httpClient http.Client
	key        string
}

// KeyRequest handles /v1/key/request API call.
// On success API key is returned.
func (c *Client) KeyRequest() (string, error) {
	payload, err := json.Marshal(createKeyRequest())
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, c.Server+request, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent+c.Version)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err
	}

	if err = response.Body.Close(); err != nil {
		return "", err
	}

	if err != nil {
		return "", err
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
	req, err := http.NewRequest(http.MethodGet, c.Server+status, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent+c.Version)
	req.SetBasicAuth(c.key, "")

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if err = response.Body.Close(); err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
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
	payload, err := json.Marshal(*data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, c.Server+register, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.key, "")
	req.Header.Set("User-Agent", userAgent+c.Version)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer func() {
		if errClose := response.Body.Close(); errClose != nil && err == nil {
			err = errClose
		}
	}()

	if response.StatusCode != http.StatusOK {
		respBody, err := ioutil.ReadAll(response.Body)
		if err != nil {
			return err
		}
		return payloadToError(respBody)
	}

	return nil
}

// Events handles /v1/events API call.
func (c *Client) Events(follow string) (*EventsResp, error) {
	url := c.Server + events + "?follow=" + follow

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.key, "")
	req.Header.Set("User-Agent", userAgent+c.Version)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
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
	payload, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, c.Server+queries, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.key, "")
	req.Header.Set("User-Agent", userAgent+c.Version)

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	respBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
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
