package AlphaSocAPI

import (
	"os"
	"testing"
	"time"
)

//todo server as env variable ASOC_TEST_SERVER
func TestStatus(t *testing.T) {
	server := os.Getenv("ASOC_TEST_SERVER")
	if server == "" {
		return
	}

	if os.Getenv("ASOC_API_KEY") != "" {
		return
	}

	c := Client{Server: server}
	k, err := c.KeyRequest()
	if err != nil {
		t.Errorf("KeyRequest() unexpected error: %q", err)
	}

	if k == "" {
		t.Errorf("KeyRequest() expected non empty key")
	}

	c.SetKey(k)

	time.Sleep(time.Millisecond * 100)

	status, errs := c.AccountStatus()
	if errs != nil {
		t.Errorf("AccountStatus() unexpected error: %q", err)
	}

	if status == nil {
		t.Errorf("AccountStatus() returned nil status")
	}

	if status.Registered == true {
		t.Errorf("AccountStatus() expected unregistered account")
	}

	reg := RegisterReq{}
	reg.Details.Address[0] = "hell"
	reg.Details.Email = "namescore_test@alphasoc.com"
	reg.Details.Name = "namescore"
	reg.Details.Organization = "AlphaSOC"
	reg.Details.Phone = "123-456-789"

	if err := c.Register(&reg); err != nil {
		t.Errorf("Register() failed err=%v", err)
	}

	statusreg, errsg := c.AccountStatus()
	if errsg != nil {
		t.Errorf("AccountStatus() on registered account, unexpected error: %q", err)
	}
	if statusreg == nil {
		t.Errorf("AccountStatus() on registered account, returned nil status")
	}

	if status.Registered == false {
		t.Errorf("AccountStatus() expected registered account")
	}
}

func TestStatusSick(t *testing.T) {
	server := os.Getenv("ASOC_TEST_SERVER")
	if server == "" {
		return
	}

	key := os.Getenv("ASOC_API_KEY")
	if key == "" {
		return
	}

	c := Client{Server: server}
	k, err := c.KeyRequest()
	if err == nil {
		t.Errorf("KeyRequest() expected error (sick mode)")
	}

	if k != "" {
		t.Errorf("KeyRequest() expected empty key")
	}

	c.SetKey(key)

	status, errs := c.AccountStatus()
	if errs != nil {
		t.Errorf("AccountStatus() unexpected error: %q", err)
	}

	if status.Registered == false {
		t.Errorf("AccountStatus() expected registered account")
	}

}
