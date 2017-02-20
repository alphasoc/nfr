package asoc

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestQueryStoreNoFiles(t *testing.T) {
	s := NewQueryStore(10, "/tmp")

	if nil != s.GetQueryFiles() {
		t.Errorf("getQueryFiles did not return nil on non existing directory")
	}
}

func TestQueryStoreName(t *testing.T) {
	s := NewQueryStore(10, "/tmp")

	name := s.GenerateName()

	if strings.HasPrefix(name, s.dir) == false {
		t.Fatalf("GenerateName()=%q expected to have prefix %s,", name, s.dir)
	}
}

func TestQueryStore(t *testing.T) {

	entrya := Entry{FQDN: "possible-dga.com", IP: net.ParseIP("1.1.1.1"), QType: "A", Time: time.Now()}
	entryb := Entry{FQDN: "google.com", IP: net.ParseIP("1.5.2.1"), QType: "TXT", Time: time.Now()}

	dataa := []Entry{entrya}
	datab := []Entry{entrya, entryb}
	datac := []Entry{entrya, entryb, entrya}

	querya := &QueriesReq{Data: dataa}
	queryb := &QueriesReq{Data: datab}
	queryc := &QueriesReq{Data: datac}

	dir := "/tmp/namescore_query_test"
	if err := os.Mkdir(dir, 0770); err != nil {
		t.Fatalf("Mkdir(%q) failed, err=%v", dir, err)
	}
	defer os.RemoveAll(dir)

	s := NewQueryStore(10, dir)
	if nil != s.GetQueryFiles() {
		t.Fatalf("getQueryFiles did not return nil on non existing directory")
	}

	if err := s.Store(querya); err != nil {
		t.Fatalf("Store(querya) failed, err=%v", err)
	}

	if err := s.Store(queryb); err != nil {
		t.Fatalf("Store(queryb) failed, err=%v", err)
	}

	if err := s.Store(queryc); err != nil {
		t.Fatalf("Store(queryc) failed, err=%v", err)
	}

	files := s.GetQueryFiles()
	if len(files) != 3 {
		t.Fatalf("getQueryFiles() returned %d files, expected 3", len(files))
	}

	for _, file := range files {
		q, err := s.Read(file)
		if err != nil {
			t.Fatalf("Read(%q) returned err=%v", file, err)
		}
		if q == nil {
			t.Fatalf("Read(%q) returned empty queries", file)
		}
		if len(q.Data) == 0 {
			t.Fatalf("Read(%q) data length is 0", file)
		}
		if q.Data[0].FQDN == "" {
			t.Fatalf("Read(%q) read FQDN is empty", file)
		}
		if q.Data[0].IP == nil {
			t.Fatalf("Read(%q) read IP is empty", file)
		}
		if q.Data[0].QType == "" {
			t.Fatalf("Read(%q) read QTYPE is empty", file)
		}
		if q.Data[0].Time.String() == "" {
			t.Fatalf("Read(%q) read Time is empty", file)
		}
	}

}
