package utils

import (
	"log"
	"os"
	"time"

	"github.com/alphasoc/namescore/client"
)

type Poller struct {
	c          client.Client
	l          EventsLogger
	timer      time.Timer
	followFile string
}

func NewPoller(c client.Client, l EventsLogger) *Poller {
	return &Poller{
		c: c,
		l: l,
	}
}

func (p *Poller) SetFollowDatafile(file string) {
	p.followFile = file
}

func (p *Poller) Poll(interval time.Duration) {
	var follow = ""
	timer := time.NewTimer(interval)
	for range timer.C {
		events, err := p.c.Events(follow)
		if err != nil {
			log.Println(err)
			continue
		}
		if err := p.l.Log(events); err != nil {
			log.Println(err)
			continue
		}
		follow = events.Follow
		if p.followFile != "" {
			f, err := os.OpenFile(p.followFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				log.Println(err)
				continue
			}
			f.WriteString(follow)
			f.Close()
		}
	}
}

func (p *Poller) Stop() {
	p.timer.Stop()
}
