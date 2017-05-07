package events

import (
	"encoding/json"
	"os"
	"log"
	"time"

	"github.com/alphasoc/namescore/client"
)

type Logger interface {
	Log(*client.EventsResponse) error
}

type JSONFileLogger struct {
	f *os.File
}

func NewJSONFileLogger(file string) (Logger, error) {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		return nil, err
	}

	return &JSONFileLogger{f}, nil
}

func (l *JSONFileLogger) Log(e *client.EventsResponse) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}

	_, err = l.f.Write(b)
	return err
}

func (l *JSONFileLogger) Close() error {
	return l.f.Close()
}

type Poller struct {
	c *client.Client
	l Logger
	timer time.Timer
	followFile string
}

func NewPoller(c *client.Client, l Logger) *Poller {
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
			f, err := os.OpenFile(p.followFile, os.O_WRONLY|os.O_CREATE|os.O_TROUNCLE, 0644)
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
