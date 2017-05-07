package client

// MockAlphaSOCClient creates Client for testing.
type MockAlphaSOCClient struct{}

// NewMockClient creates new AlphaSOC mock client for testing.
func NewMockClient() Client {
	return &MockAlphaSOCClient{}
}

// AccountRegister mock.
func (c *MockAlphaSOCClient) AccountRegister(req *AccountRegisterRequest) error {
	return nil
}

// AccountStatus mock.
func (c *MockAlphaSOCClient) AccountStatus() (*AccountStatusResponse, error) {
	return &AccountStatusResponse{}, nil
}

// Events mock.
func (c *MockAlphaSOCClient) Events(follow string) (*EventsResponse, error) {
	return &EventsResponse{}, nil
}

// Queries mock.
func (c *MockAlphaSOCClient) Queries(req *QueriesRequest) (*QueriesResponse, error) {
	return &QueriesResponse{}, nil
}

// KeyRequest mock.
func (c *MockAlphaSOCClient) KeyRequest() (*KeyRequestResponse, error) {
	return &KeyRequestResponse{}, nil
}

// KeyReset mock.
func (c *MockAlphaSOCClient) KeyReset(req *KeyResetRequest) error {
	return nil
}
