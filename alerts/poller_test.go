// Package alerts polls and writes alerts from AlphaSOC Engine.
package alerts

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/groups"
)

func TestPollerDo(t *testing.T) {
	const fname = "_alerts"
	defer os.Remove(fname)

	w, err := NewJSONFileWriter(fname)
	if err != nil {
		t.Fatal(err)
	}

	p := NewPoller(client.NewMock(), NewAlertMapper(groups.New()))
	p.AddWriter(w)
	p.follow = "1"
	p.do(1, 1)

	b, err := ioutil.ReadFile(fname)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != "" {
		t.Fatal("no alerts should be written to file")
	}
}
