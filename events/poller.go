package events

import (
	"io/ioutil"
	"os"
	"time"

	"github.com/alphasoc/namescore/client"
)

type Poller struct {
	c          client.Client
	l          Logger
	ticker     *time.Ticker
	follow     string
	followFile string
}

func NewPoller(c client.Client, l Logger) *Poller {
	return &Poller{
		c: c,
		l: l,
	}
}

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

func (p *Poller) Do(interval time.Duration) error {
	p.ticker = time.NewTicker(interval)
	defer p.stop()

	for range p.ticker.C {
		events, err := p.c.Events(p.follow)
		if err != nil {
			return err
		}

		if err := p.l.Log(events); err != nil {
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

func (p *Poller) stop() {
	if p.ticker != nil {
		p.ticker.Stop()
		p.ticker = nil
	}
}
