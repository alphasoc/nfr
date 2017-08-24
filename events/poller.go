// Package events polls and writes events from AlphaSOC api.
package events

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/alphasoc/nfr/client"
)

// Poller polls events from AlphaSOC api and user logger
// to store it into writer
type Poller struct {
	c          client.Client
	l          Writer
	ticker     *time.Ticker
	follow     string
	followFile string
}

// NewPoller creates new poller base on give client and writer.
func NewPoller(c client.Client, l Writer) *Poller {
	return &Poller{
		c: c,
		l: l,
	}
}

// SetFollowDataFile sets file for storing follow id.
// If not used then poller will be retriving all events from the beging.
// If set then only new events are polled.
func (p *Poller) SetFollowDataFile(file string) error {
	p.followFile = file

	// try to read existing follow id
	b, err := ioutil.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	p.follow = string(b)
	return nil
}

// Do polls events within a period specified by the interval argument.
// The events are writtne to writer used to create new poller.
// If the error occurrs Do method should be call again.
func (p *Poller) Do(interval time.Duration) error {
	p.ticker = time.NewTicker(interval)
	defer p.stop()

	for range p.ticker.C {
		events, err := p.c.Events(p.follow)
		if err != nil {
			return err
		}

		if err := p.l.Write(events); err != nil {
			return err
		}

		if p.follow == events.Follow {
			continue
		}

		p.follow = events.Follow
		if p.followFile != "" {
			if err := ioutil.WriteFile(p.followFile, []byte(p.follow), 0644); err != nil {
				return err
			}
		}
	}
	panic("not reached")
}

// stop stops poller do, by stoping ticker.
func (p *Poller) stop() {
	if p.ticker != nil {
		p.ticker.Stop()
		p.ticker = nil
	}
}
