package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/alphasoc/namescore/asoc"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/utils"
	"github.com/google/gopacket"
	log "github.com/inconshreveable/log15"
)

// Test: AlertsLoop test when AccountStatus always fails
//
// Expectations:
// - asoc.Events should not be called
// - follow should not be updated
func TestAlertsLoopStatusFail(t *testing.T) {
	cfg := &config.Config{
		AlertRequestInterval: 1 * time.Millisecond,
	}
	quit := make(chan bool)
	notify := make(chan bool)

	handler := listenHandler{
		logger:     dummyLogger(),
		queryStore: asoc.NewQueryStore(0, "/tmp"),
		sniffer:    &FatalSniffer{},
		cfg:        cfg,
		quit:       quit,
		client:     &FailingClientOnAccountStatus{notify: notify},
	}
	go handler.AlertsLoop()
	<-notify
	quit <- true
}

// Client that always returns error.
// When AccountStatus is called info is sent to channel.
// It also calls t.Fatalf if Events() is called
type FailingClientOnAccountStatus struct {
	t      *testing.T
	notify chan bool
}

func (a *FailingClientOnAccountStatus) KeyRequest() (string, error) {
	return "", fmt.Errorf("keyRequest")

}
func (a *FailingClientOnAccountStatus) SetKey(key string) {

}
func (a *FailingClientOnAccountStatus) AccountStatus() (*asoc.StatusResp, error) {
	a.notify <- true
	return nil, fmt.Errorf("accountStatus")

}
func (a *FailingClientOnAccountStatus) Register(data *asoc.RegisterReq) error {
	return fmt.Errorf("register")

}
func (a *FailingClientOnAccountStatus) Events(follow string) (*asoc.EventsResp, error) {
	a.t.Fatalf("Events function shouldn't be called in this scenario.")
	return nil, fmt.Errorf("events")

}
func (a *FailingClientOnAccountStatus) Queries(q *asoc.QueriesReq) (*asoc.QueriesResp, error) {
	return nil, fmt.Errorf("queries")
}

// Sniffer that calls t.Fatalf if called
type FatalSniffer struct {
	t *testing.T
}

func (d *FatalSniffer) Sniff() gopacket.Packet {
	d.t.Fatalf("Sniff function shouldn't be called in this scenario.")
	return nil
}

func (d *FatalSniffer) PacketToEntry(packet gopacket.Packet) []asoc.Entry {
	d.t.Fatalf("PacketToEntry function shouldn't be called in this scenario.")
	return nil
}

func (d *FatalSniffer) Close() {
	d.t.Fatalf("Close function shouldn't be called in this scenario.")
}

// Test: AlertsLoop test when AccountStatus returns always correct status,
//       but Events return error and dummy follow
// Expectations:
// - alertStore should not be created
// - follow should not be updated by dummy follow
func TestAlertsLoopEventsFail(t *testing.T) {
	followFile := os.TempDir() + "/nonExist_follow_file"
	cfg := &config.Config{
		AlertRequestInterval: 1 * time.Millisecond,
		FollowFilePath:       followFile,
	}
	quit := make(chan bool)
	notify := make(chan bool)

	handler := listenHandler{
		logger:     dummyLogger(),
		queryStore: asoc.NewQueryStore(0, "/tmp"),
		sniffer:    &FatalSniffer{},
		cfg:        cfg,
		quit:       quit,
		client:     &FailingClientOnEvents{notify: notify},
	}
	go handler.AlertsLoop()
	<-notify
	quit <- true

	exist, err := utils.FileExists(followFile)
	if err != nil {
		t.Fatalf("FileExists(%q) unexpected error=%v", followFile, err)
	}
	if exist {
		t.Fatalf("Follow file %q shouldn't be created in this scenario.", followFile)
	}
}

// When Events is called info is sent to channel.
// It also calls t.Fatalf if Events() is called
type FailingClientOnEvents struct {
	t      *testing.T
	notify chan bool
}

func (a *FailingClientOnEvents) KeyRequest() (string, error) {
	return "", fmt.Errorf("keyRequest")

}
func (a *FailingClientOnEvents) SetKey(key string) {

}
func (a *FailingClientOnEvents) AccountStatus() (*asoc.StatusResp, error) {
	resp := &asoc.StatusResp{Registered: true, Expired: false}
	return resp, nil

}
func (a *FailingClientOnEvents) Register(data *asoc.RegisterReq) error {
	return fmt.Errorf("register")

}
func (a *FailingClientOnEvents) Events(follow string) (*asoc.EventsResp, error) {
	a.notify <- true
	return nil, fmt.Errorf("events")

}
func (a *FailingClientOnEvents) Queries(q *asoc.QueriesReq) (*asoc.QueriesResp, error) {
	return nil, fmt.Errorf("queries")
}

// getAlerts happy path test
// - alertStore contain gathered alerts
// - follow should be updated
func TestAlertsLoopHappyPath(t *testing.T) {
	followFile := os.TempDir() + "/test_follow_file"
	alertFile := os.TempDir() + "/test_alerts"
	loopCount := 10

	cfg := &config.Config{
		AlertRequestInterval: 1 * time.Millisecond,
		FollowFilePath:       followFile,
		AlertFilePath:        alertFile,
	}
	quit := make(chan bool)
	notify := make(chan bool)

	handler := listenHandler{
		logger:     dummyLogger(),
		queryStore: asoc.NewQueryStore(0, "/tmp"),
		sniffer:    &FatalSniffer{},
		cfg:        cfg,
		quit:       quit,
		client:     &ClientPositiveEvents{notify: notify, t: t},
	}
	exist, err := utils.FileExists(followFile)
	if err != nil {
		t.Fatalf("FileExists(%q) unexpected error=%v", followFile, err)
	}
	if exist {
		t.Fatalf("Follow file %q shouldn't be created before this scenario.", followFile)
	}

	fexist, err := utils.FileExists(alertFile)
	if err != nil {
		t.Fatalf("FileExists(%q) unexpected error=%v", alertFile, err)
	}
	if fexist {
		t.Fatalf("Alert file %q shouldn't be created before this scenario.", alertFile)
	}

	defer func() {
		if err := os.Remove(followFile); err != nil {
			t.Fatalf("Remove(%q) unexpected error=%v", followFile, err)
		}
		if err := os.Remove(alertFile); err != nil {
			t.Fatalf("Remove(%q) unexpected error=%v", alertFile, err)
		}
	}()

	go handler.AlertsLoop()
	for i := 0; i < loopCount; i++ {
		<-notify
	}
	quit <- true

	followRead, err := ioutil.ReadFile(followFile)
	if err != nil {
		t.Fatalf("ReadFile(%q) unexpected error=%v", followFile, err)
	}

	if string(followRead) != strconv.Itoa(loopCount) {
		t.Fatalf("Expected to have follow stored %q, got %q", string(followRead), strconv.Itoa(loopCount))
	}

	alertRead, err := ioutil.ReadFile(alertFile)
	if err != nil {
		t.Fatalf("ReadFile(%q) unexpected error=%v", alertFile, err)
	}
	scanner := bufio.NewScanner(bytes.NewBuffer(alertRead))
	var lineCount int
	for scanner.Scan() {
		lineCount++
	}

	if lineCount != loopCount {
		t.Fatalf("Expected to have %d alerts stored, %d", loopCount, lineCount)
	}
}

// Client that returns OK on calls AccountStatus and Events
type ClientPositiveEvents struct {
	// In this test followID is number of iteration
	retFollow     int
	firstCallDone bool
	t             *testing.T
	notify        chan bool
}

func (a *ClientPositiveEvents) KeyRequest() (string, error) {
	return "", fmt.Errorf("keyRequest")

}
func (a *ClientPositiveEvents) SetKey(key string) {

}
func (a *ClientPositiveEvents) AccountStatus() (*asoc.StatusResp, error) {
	resp := &asoc.StatusResp{Registered: true, Expired: false}
	return resp, nil

}
func (a *ClientPositiveEvents) Register(data *asoc.RegisterReq) error {
	return fmt.Errorf("register")

}
func (a *ClientPositiveEvents) Events(follow string) (*asoc.EventsResp, error) {
	if a.firstCallDone == false {
		if follow != "" {
			a.t.Fatalf("First Events call should be with empty follow, got %s", follow)
		}
		a.firstCallDone = true
	} else {
		if strconv.Itoa(a.retFollow) != follow {
			a.t.Fatalf("Follow mismatch, expected %d got %s", a.retFollow, follow)
		}
	}

	a.retFollow++

	dummyEvent := asoc.EventDetail{
		Type:  "alert",
		Risk:  1,
		FQDN:  "alphasoc.com",
		IP:    "127.0.0.1",
		QType: "TXT",
		Ts:    []string{"2015-06-09T16:54:59Z"},
	}
	resp := &asoc.EventsResp{
		Follow: strconv.Itoa(a.retFollow),
		Events: []asoc.EventDetail{dummyEvent},
	}
	a.notify <- true
	return resp, nil
}

func (a *ClientPositiveEvents) Queries(q *asoc.QueriesReq) (*asoc.QueriesResp, error) {
	return nil, fmt.Errorf("Queries")
}

// queries from local files test
// - generate 10 files with query data
// - call LocalQueriesLoop()
// - check if files were send and removed
func TestAlertsLocalQueriesLoop(t *testing.T) {
	followFile := os.TempDir() + "/nonExist_follow_file"
	queriesCount := 10

	cfg := &config.Config{
		LocalQueriesInterval: 1 * time.Millisecond,
		FailedQueriesDir:     os.TempDir(),
		FailedQueriesLimit:   queriesCount,
	}
	quit := make(chan bool)
	notify := make(chan bool, queriesCount)

	handler := listenHandler{
		logger:     dummyLogger(),
		queryStore: asoc.NewQueryStore(queriesCount, os.TempDir()),
		sniffer:    &FatalSniffer{},
		cfg:        cfg,
		quit:       quit,
		client:     &ClientAcceptingLocalQueries{notify: notify},
	}

	if files, err := handler.queryStore.GetQueryFiles(); err != nil {
		t.Fatalf("GetQueryFiles() unexpected error=%v", err)
	} else if len(files) > 0 {
		t.Fatalf("There shouldn't be any query files before test.")
	}

	if err := generateQueryFiles(queriesCount, &handler); err != nil {
		t.Fatalf("During creating test files unexpected error: %v", err)
	}

	go handler.LocalQueriesLoop()
	for i := 0; i < queriesCount; i++ {
		<-notify
	}
	quit <- true

	exist, err := utils.FileExists(followFile)
	if err != nil {
		t.Fatalf("FileExists(%q) unexpected error=%v", followFile, err)
	}
	if exist {
		t.Fatalf("Follow file %q shouldn't be created in this scenario.", followFile)
	}

	if files, err := handler.queryStore.GetQueryFiles(); err != nil {
		t.Fatalf("GetQueryFiles() unexpected error=%v", err)
	} else if len(files) > 0 {
		t.Fatalf("All queries should be removed during test.")
	}
}

// Client that accepts Queries, other calls make test fail.
type ClientAcceptingLocalQueries struct {
	t      *testing.T
	notify chan bool
}

func (a *ClientAcceptingLocalQueries) KeyRequest() (string, error) {
	return "", fmt.Errorf("keyRequest")

}
func (a *ClientAcceptingLocalQueries) SetKey(key string) {

}
func (a *ClientAcceptingLocalQueries) AccountStatus() (*asoc.StatusResp, error) {
	return nil, fmt.Errorf("accountStatus")

}
func (a *ClientAcceptingLocalQueries) Register(data *asoc.RegisterReq) error {
	return fmt.Errorf("register")

}
func (a *ClientAcceptingLocalQueries) Events(follow string) (*asoc.EventsResp, error) {
	a.t.Fatalf("Events function shouldn't be called in this scenario.")
	return nil, fmt.Errorf("events")

}
func (a *ClientAcceptingLocalQueries) Queries(q *asoc.QueriesReq) (*asoc.QueriesResp, error) {
	resp := &asoc.QueriesResp{Received: 1, Accepted: 1}
	a.notify <- true
	return resp, nil
}

// Common functions
func dummyLogger() log.Logger {
	logger := log.New()
	logger.SetHandler(log.DiscardHandler())
	return logger
}

func generateQueryFiles(count int, l *listenHandler) error {
	entries := []asoc.Entry{asoc.Entry{FQDN: "possible-dga.com", IP: net.ParseIP("1.1.1.1"), QType: "A", Time: time.Now()}}
	req := &asoc.QueriesReq{Data: entries}

	for i := 0; i < count; i++ {
		if err := l.queryStore.Store(req); err != nil {
			return err
		}
	}
	return nil
}
