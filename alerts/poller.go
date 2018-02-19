// Package alerts polls and writes alerts from AlphaSOC api.
package alerts

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/alphasoc/nfr/client"
)

// Poller polls alerts from AlphaSOC api and user logger
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
// If not used then poller will be retriving all alerts from the beging.
// If set then only new alerts are polled.
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

// Do polls alerts within a period specified by the interval argument.
// The alerts are writtne to writer used to create new poller.
// If the error occurrs Do method should be call again.
func (p *Poller) Do(interval time.Duration) error {
	return p.do(interval, 0)
}

// do pools maxiumum "count" alerts. If count <=0 then it pulls forever.
func (p *Poller) do(interval time.Duration, count int) error {
	p.ticker = time.NewTicker(interval)
	defer p.stop()

	var c = 0
	for range p.ticker.C {
		alerts, err := p.c.Alerts(p.follow)
		if err != nil {
			return err
		}

		if err := p.l.Write(alerts); err != nil {
			return err
		}

		if p.follow == alerts.Follow {
			continue
		}

		p.follow = alerts.Follow
		if p.followFile != "" {
			if err := ioutil.WriteFile(p.followFile, []byte(p.follow), 0644); err != nil {
				return err
			}
		}

		c++
		if count > 0 && c >= count {
			break
		}
	}
	return nil
}

// stop stops poller do, by stoping ticker.
func (p *Poller) stop() {
	if p.ticker != nil {
		p.ticker.Stop()
		p.ticker = nil
	}
}
