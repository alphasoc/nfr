package cmd

import (
	"fmt"
	"testing"

	"github.com/alphasoc/namescore/internal/config"

	"time"

	"github.com/alphasoc/namescore/internal/asoc"
	"github.com/google/gopacket"
	log "github.com/inconshreveable/log15"
)

// Test: AlertsLoop test when AccountStatus always fails
//
// Expectations:
// - asoc.Events should not be called
// - follow should not be updated
func TestGetAlertsStatusFail(t *testing.T) {

	cfg := &config.Config{
		AlertRequestInterval: 10 * time.Millisecond,
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
}

// Client that always returns error.
// When AccountStatus is called info is sent to channel.
// It also calls t.Fatalf if Events() is called
type FailingClientOnEvents struct {
	t      *testing.T
	notify chan bool
}

func (a *FailingClientOnEvents) KeyRequest() (string, error) {
	return "", fmt.Errorf("KeyRequest")

}
func (a *FailingClientOnEvents) SetKey(key string) {

}
func (a *FailingClientOnEvents) AccountStatus() (*asoc.StatusResp, error) {
	a.notify <- true
	return nil, fmt.Errorf("AccountStatus")

}
func (a *FailingClientOnEvents) Register(data *asoc.RegisterReq) error {
	return fmt.Errorf("Register")

}
func (a *FailingClientOnEvents) Events(follow string) (*asoc.EventsResp, error) {
	a.t.Fatalf("Events function shouldn't be called in this scenario.")
	return nil, fmt.Errorf("Events")

}
func (a *FailingClientOnEvents) Queries(q *asoc.QueriesReq) (*asoc.QueriesResp, error) {
	return nil, fmt.Errorf("Queries")

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

// getAlerts happy path test
// - alertStore contain gathered alerts
// - follow should be updated
// - no warning logs

// queries test when asoc.Queries fails
// limit for files should be set to 10
// fake DNSCapture should return 100 queries
// - queries should be stored to file
// - no more than 10 files with queries

// queries test when asoc.Queries returns all rejected
//  - warning should be written
// -  no files qith queries created

// queries from local files test
// - generate 10 blocks of data
// - fail on sending
// - read them from file
// - accept from sending function

// Common functions
func dummyLogger() log.Logger {
	logger := log.New()
	logger.SetHandler(log.DiscardHandler())
	return logger
}
