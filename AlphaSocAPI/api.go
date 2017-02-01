package AlphaSocAPI

import (
	"bytes"
	"encoding/json"
	"fmt"
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

type Client struct {
	Server     string
	httpClient http.Client
	key        string
}

func (c *Client) KeyRequest() (string, error) {
	payload, errj := json.Marshal(createKeyRequest())

	if errj != nil {
		return "", fmt.Errorf("Request(), json err=%q", errj)
	}

	response, errp := c.httpClient.Post(c.Server+request, "application/json", bytes.NewReader(payload))
	if errp != nil {
		return "", fmt.Errorf("Request(), POST err=%q", errp)
	}

	respBody, errb := ioutil.ReadAll(response.Body)
	response.Body.Close()

	if errb != nil {
		return "", fmt.Errorf("Request(), response reading err=%q", errb)
	}

	if response.StatusCode != 200 {
		return "", payloadToError(respBody)
	}

	key := keyReqResp{}
	if e := json.Unmarshal(respBody, &key); e != nil {
		return "", fmt.Errorf("Request(), unmarshalling err=%v", e)
	}

	return key.Key, nil
}

func (c *Client) SetKey(key string) {
	c.key = key
}

func (c *Client) AccountStatus() (*StatusResp, error) {
	req, errn := http.NewRequest("GET", c.Server+status, nil)
	if errn != nil {
		return nil, fmt.Errorf("AccountStatus(), request creating err=%v", errn)
	}

	req.SetBasicAuth(c.key, "")

	response, errd := c.httpClient.Do(req)
	if errd != nil {
		return nil, fmt.Errorf("AccountStatus() doing request err=%v", errd)
	}

	respBody, errb := ioutil.ReadAll(response.Body)
	response.Body.Close()
	if errb != nil {
		return nil, fmt.Errorf("AccountStatus() body reading err=%v", errb)
	}

	if response.StatusCode != 200 {
		return nil, payloadToError(respBody)
	}

	status := StatusResp{}
	if e := json.Unmarshal(respBody, &status); e != nil {
		return nil, fmt.Errorf("AccountStatus(), unmarshalling err=%v", e)
	}

	return &status, nil
}

func (c *Client) Register(data *RegisterReq) error {
	payload, errj := json.Marshal(*data)

	if errj != nil {
		return fmt.Errorf("Register(), json err=%q", errj)
	}

	req, errn := http.NewRequest("POST", c.Server+register, bytes.NewReader(payload))
	if errn != nil {
		return fmt.Errorf("Register(), request creating err=%v", errn)
	}
	req.SetBasicAuth(c.key, "")

	response, errd := c.httpClient.Do(req)
	if errd != nil {
		return fmt.Errorf("Register() doing request err=%v", errd)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		respBody, errb := ioutil.ReadAll(response.Body)
		if errb != nil {
			return fmt.Errorf("Register() body reading err=%v", errb)
		}
		return payloadToError(respBody)
	}

	return nil
}

func VerifyKey(key string) bool {
	if len(key) < 15 {
		return false
	}
	return true
}
