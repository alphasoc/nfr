package client

import (
	"context"
	"io/ioutil"
	"log"
)

// AccountRegisterRequest contains information needed to
// register alphasoc account and obtain API key.
type AccountRegisterRequest struct {
	Details struct {
		Name         string    `json:"name"`
		Organization string    `json:"organization"`
		Email        string    `json:"email"`
		Phone        string    `json:"phone"`
		Address      [3]string `json:"address"`
	} `json:"details"`
}

// AccountRegister registers new alphasoc account.
func (c *Client) AccountRegister(req *AccountRegisterRequest) error {
	resp, err := c.post(context.Background(), "account/register", nil, req)
	if err != nil {
		return err
	}
	b, _ := ioutil.ReadAll(resp.Body)
	log.Println(resp.StatusCode, string(b))
	resp.Body.Close()
	return err
}
