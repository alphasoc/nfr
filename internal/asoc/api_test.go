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

	qresp, errquery := c.Queries(&query)
	if errquery != nil {
		t.Fatalf("Queries() unexpected err=%v", errquery)
	}

	if qresp.Received != len(query.Data) {
		t.Fatalf("Queries() data len=%d, but received=%d", len(query.Data), qresp.Received)
	}

	eventone, errone := c.Events(follow)
	if errone != nil {
		t.Fatalf("Events() unexpected error: %q", errone)
	}

	if eventone == nil {
		t.Fatalf("Events() unexpected eventone=nil")
	}
}

func TestWrongServer(t *testing.T) {

	var (
		server = "invalid address"
	)

	client := Client{Server: server}

	if status, err := client.AccountStatus(); err == nil {
		t.Fatalf("AccountStatus() expected error")
	} else if status != nil {
		t.Fatalf("AccountStatus() expected nil status")
	}

	if events, err := client.Events(""); err == nil {
		t.Fatalf("Events() expected error")
	} else if events != nil {
		t.Fatalf("Events() expected nil events")
	}

	if key, err := client.KeyRequest(); err == nil {
		t.Fatalf("KeyRequest() expected error")
	} else if key != "" {
		t.Fatalf("KeyRequest() expected empty key")
	}

	reg := &RegisterReq{}
	if err := client.Register(reg); err == nil {
		t.Fatalf("Register() expected error")
	}

	qry := &QueriesReq{}
	if qresp, err := client.Queries(qry); err == nil {
		t.Fatalf("Queries() expected error")
	} else if qresp != nil {
		t.Fatalf("Queries() expected nil response")
	}
}

func TestWrongServerWithKey(t *testing.T) {
	var (
		server = "invalid address"
		key    = "key"
	)

	client := Client{Server: server}
	client.SetKey(key)

	if status, err := client.AccountStatus(); err == nil {
		t.Fatalf("AccountStatus() expected error")
	} else if status != nil {
		t.Fatalf("AccountStatus() expected nil status")
	}

	if events, err := client.Events(""); err == nil {
		t.Fatalf("Events() expected error")
	} else if events != nil {
		t.Fatalf("Events() expected nil events")
	}

	if key, err := client.KeyRequest(); err == nil {
		t.Fatalf("KeyRequest() expected error")
	} else if key != "" {
		t.Fatalf("KeyRequest() expected empty key")
	}

	reg := &RegisterReq{}
	if err := client.Register(reg); err == nil {
		t.Fatalf("Register() expected error")
	}

	qry := &QueriesReq{}
	if qresp, err := client.Queries(qry); err == nil {
		t.Fatalf("Queries() expected error")
	} else if qresp != nil {
		t.Fatalf("Queries() expected nil response")
	}
}
