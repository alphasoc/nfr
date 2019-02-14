package client

// MockAlphaSOCClient creates Client for testing.
type MockAlphaSOCClient struct{}

// NewMock creates new AlphaSOC mock client for testing.
func NewMock() Client {
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

// Alerts mock.
func (c *MockAlphaSOCClient) Alerts(follow string) (*AlertsResponse, error) {
	return &AlertsResponse{}, nil
}

// EventsDNS mock.
func (c *MockAlphaSOCClient) EventsDNS(req *EventsDNSRequest) (*EventsDNSResponse, error) {
	return &EventsDNSResponse{}, nil
}

// EventsIP mock.
func (c *MockAlphaSOCClient) EventsIP(req *EventsIPRequest) (*EventsIPResponse, error) {
	return &EventsIPResponse{}, nil
}

func (c *MockAlphaSOCClient) EventsHTTP(req []*HTTPEntry) (*EventsHTTPResponse, error) {
	return &EventsHTTPResponse{}, nil
}

// KeyRequest mock.
func (c *MockAlphaSOCClient) KeyRequest() (*KeyRequestResponse, error) {
	return &KeyRequestResponse{}, nil
}

// KeyReset mock.
func (c *MockAlphaSOCClient) KeyReset(req *KeyResetRequest) error {
	return nil
}
