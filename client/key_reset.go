package client

import "context"

// KeyResetRequest contasin information needed for key reset.
type KeyResetRequest struct {
	Email string `json:"email"`
}

// KeyReset reset AlphaSOC account key.
func (c *AlphaSOCClient) KeyReset(req *KeyResetRequest) error {
	resp, err := c.post(context.Background(), "key/reset", nil, req, false)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
