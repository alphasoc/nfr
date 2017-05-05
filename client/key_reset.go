package client

import "context"

// KeyResetRequest contasin infromation needed for key reset.
type KeyResetRequest struct {
	Email string `json:"email"`
}

// KeyReset reset AlphaSOC account key.
func (c *Client) KeyReset(req *KeyResetRequest) error {
	resp, err := c.post(context.Background(), "key/reset", nil, req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
