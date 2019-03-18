// Package alerts polls and writes alerts from AlphaSOC Engine.
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
	writers    []Writer
	ticker     *time.Ticker
	follow     string
	followFile string
	mapper     *AlertMapper
}

// NewPoller creates new poller base on give client and writer.
func NewPoller(c client.Client, mapper *AlertMapper) *Poller {
	return &Poller{
		c:       c,
		writers: make([]Writer, 0),
		mapper:  mapper,
	}
}

// AddWriter adds writer to poller.
func (p *Poller) AddWriter(w Writer) {
	p.writers = append(p.writers, w)
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
// The alerts are written to writer used to create new poller.
// If the error occurrs Do method should be call again.
func (p *Poller) Do(interval time.Duration) error {
	return p.do(interval, 0)
}

// do polls alerts. If maxTries <=0 then it polls forever.
func (p *Poller) do(interval time.Duration, maxTries int) error {
	var tries = 0
	var more bool

	for {
		// if there is more to fetch then don't wait for ticker
		if !more {
			time.Sleep(interval)
		}

		if maxTries > 0 && tries >= maxTries {
			break
		}
		tries++

		alerts, err := p.c.Alerts(p.follow)
		if err == client.ErrTooManyRequests {
			time.Sleep(30 * time.Second)
			more = true
			continue
		} else if err != nil {
			return err
		}
		more = alerts.More

		if len(alerts.Alerts) == 0 {
			continue
		}

		newAlerts := p.mapper.Map(alerts)

		for _, w := range p.writers {
			for _, ev := range newAlerts.Events {
				if err := w.Write(&ev); err != nil {
					return err
				}
			}
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
