// Package events polls and writes events from AlphaSOC api.
package events

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/alphasoc/nfr/client"
)

func TestPollerDo(t *testing.T) {
	const fname = "_events"
	defer os.Remove(fname)

	w, err := NewJSONFileWriter(fname)
	if err != nil {
		t.Fatal(err)
	}

	p := NewPoller(client.NewMock(), w)
	p.follow = "1"
	p.do(1, 1)

	b, err := ioutil.ReadFile(fname)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != "" {
		t.Fatal("no events should be written to file")
	}
}
