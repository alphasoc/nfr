package client

import (
	"context"
	"fmt"
	"net/mail"
)

// AccountRegisterRequest contains information needed to
// register alphasoc account and obtain API key.
type AccountRegisterRequest struct {
	Details struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"details"`
}

// AccountRegister registers new alphasoc account.
func (c *AlphaSOCClient) AccountRegister(req *AccountRegisterRequest) error {
	if req.Details.Name == "" {
		return fmt.Errorf("name is required to register account")
	}
	if req.Details.Email == "" {
		return fmt.Errorf("email is required to register account")
	}

	email, err := mail.ParseAddress(req.Details.Email)
	if err != nil {
		return fmt.Errorf("invalid email for register account: %s", err)
	}
	req.Details.Email = email.Address

	resp, err := c.post(context.Background(), "account/register", nil, req, false)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
