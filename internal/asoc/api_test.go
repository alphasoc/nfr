package asoc

import (
	"os"
	"testing"
	"time"
)

// Test requires set ASOC_TEST_SERVER environment variable
// This test is executed when sick mode is off.
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
		t.Fatalf("KeyRequest() unexpected error: %q", err)
	}

	if k == "" {
		t.Fatalf("KeyRequest() expected non empty key")
	}

	c.SetKey(k)

	time.Sleep(time.Millisecond * 100)

	status, errs := c.AccountStatus()
	if errs != nil {
		t.Fatalf("AccountStatus() unexpected error: %q", err)
	}

	if status == nil {
		t.Fatalf("AccountStatus() returned nil status")
	}

	if status.Registered == true {
		t.Fatalf("AccountStatus() expected unregistered account")
	}

	reg := RegisterReq{}
	reg.Details.Address[0] = "hell"
	reg.Details.Email = "namescore_test@alphasoc.com"
	reg.Details.Name = "namescore"
	reg.Details.Organization = "AlphaSOC"
	reg.Details.Phone = "123-456-789"

	if err := c.Register(&reg); err != nil {
		t.Fatalf("Register() failed err=%v", err)
	}

	statusreg, errsg := c.AccountStatus()
	if errsg != nil {
		t.Fatalf("AccountStatus() on registered account, unexpected error: %q", err)
	}
	if statusreg == nil {
		t.Fatalf("AccountStatus() on registered account, returned nil status")
	}

	if status.Registered == false {
		t.Fatalf("AccountStatus() expected registered account")
	}
}

// Test requires set ASOC_TEST_SERVER and ASOC_API_KEY environment variable
// This test is executed when sick mode is off.
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
		t.Fatalf("KeyRequest() expected error (sick mode)")
	}

	if k != "" {
		t.Fatalf("KeyRequest() expected empty key")
	}

	c.SetKey(key)

	status, errs := c.AccountStatus()
	if errs != nil {
		t.Fatalf("AccountStatus() unexpected error: %q", err)
	}

	if status.Registered == false {
		t.Fatalf("AccountStatus() expected registered account")
	}

	eventzero, errzero := c.Events("")
	if errzero != nil {
		t.Fatalf("Events() unexpected error: %q", errzero)
	}

	if eventzero == nil {
		t.Fatalf("Events() unexpected eventzero=nil")
	}
	follow := eventzero.Follow

	query := QueriesReq{Data: make([]Entry, 2)}

	var (
		date1 = "2015-06-09T16:54:59Z"
		date2 = "2015-06-09T16:55:59Z"
		ip    = "192.168.1.4"
		qtype = "A"
		fqdn  = "possible-dga.com"
	)
	query.Data[0] = Entry{date1, ip, qtype, fqdn}
	query.Data[1] = Entry{date2, ip, qtype, fqdn}

	if err := c.Queries(query); err != nil {
		t.Fatalf("Queries() unexpected err=%v", err)
	}

	eventone, errone := c.Events(follow)
	if errone != nil {
		t.Fatalf("Events() unexpected error: %q", errone)
	}

	if eventone == nil {
		t.Fatalf("Events() unexpected eventone=nil")
	}

}
