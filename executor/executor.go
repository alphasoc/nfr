// Package executor execs main loop in namescore
package executor

import (
	"log"
	"sync"
	"time"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/dns"
	"github.com/alphasoc/namescore/events"
	"github.com/alphasoc/namescore/groups"
)

type Executor struct {
	c   client.Client
	cfg *config.Config

	eventsPoller *events.Poller
	eventsLogger events.Logger

	groups *groups.Groups

	dnsWriter *dns.Writer
	sniffer   *dns.Sniffer
	buf       *dns.PacketBuffer

	mx sync.Mutex
}

func New(c client.Client, cfg *config.Config) (*Executor, error) {
	eventsLogger, err := events.NewJSONFileLogger(cfg.Events.File)
	if err != nil {
		return nil, err
	}

	eventsPoller := events.NewPoller(c, eventsLogger)
	if err := eventsPoller.SetFollowDataFile(cfg.Data.File); err != nil {
		return nil, err
	}

	groups, err := createGroups(cfg)
	if err != nil {
		return nil, err
	}

	var dnsWriter *dns.Writer
	if cfg.Queries.Failed.File != "" {
		if dnsWriter, err = dns.NewWriter(cfg.Queries.Failed.File); err != nil {
			return nil, err
		}
	}

	return &Executor{
		c:            c,
		cfg:          cfg,
		eventsPoller: eventsPoller,
		eventsLogger: eventsLogger,
		groups:       groups,
		dnsWriter:    dnsWriter,
		buf:          dns.NewPacketBuffer(),
	}, nil
}

func (e *Executor) Start() error {
	sniffer, err := dns.NewLiveSniffer(e.cfg.Network.Interface, e.cfg.Network.Protocols, e.cfg.Network.Port)
	if err != nil {
		return err
	}
	e.sniffer = sniffer
	e.sniffer.SetGroups(e.groups)

	e.startEventPoller(e.cfg.Events.PollInterval, e.cfg.Events.File, e.cfg.Data.File)
	e.startPacketSender(e.cfg.Queries.FlushInterval)

	return e.do()
}

func (e *Executor) Send(file string) error {
	sniffer, err := dns.NewOfflineSniffer(file, e.cfg.Network.Protocols, e.cfg.Network.Port)
	if err != nil {
		return err
	}
	e.sniffer = sniffer
	e.sniffer.SetGroups(e.groups)

	return e.do()
}

func (e *Executor) startEventPoller(interval time.Duration, logFile, dataFile string) {
	go func() {
		// event poller will return error from api or
		// wrinting to disk. In both cases log the error
		// and try again in a moment.
		for {
			if err := e.eventsPoller.Do(interval); err != nil {
				log.Println(err)
			}
		}
	}()
}

func (e *Executor) startPacketSender(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		for range ticker.C {
			e.sendPackets()
		}
	}()
}

func (e *Executor) sendPackets() {
	e.mx.Lock()
	packets := e.buf.Packets()
	if _, err := e.c.Queries(dnsPacketsToQueries(packets)); err != nil {
		log.Println(err)

		// try to write packets to file. If success then resset
		// buffer, else keep in buffer and try in a moment.
		if err := e.dnsWriter.Write(packets); err != nil {
			log.Println(err)
		} else {
			e.buf.Reset()
		}
	} else {
		// all packets sent, reset buffer
		e.buf.Reset()
	}
	e.mx.Unlock()
}

func (e *Executor) do() error {
	for packet := range e.sniffer.Packets() {
		e.buf.Write(packet)
		if e.buf.Len() < e.cfg.Queries.BufferSize {
			continue
		}
		e.sendPackets()
	}

	// send what left in the buffer
	e.sendPackets()
	return nil
}

func createGroups(cfg *config.Config) (*groups.Groups, error) {
	gs := groups.New()
	for name, group := range cfg.WhiteListConfig.Groups {
		g := &groups.Group{
			Name:     name,
			Includes: group.MonitoredNetwork,
			Excludes: group.ExcludedNetworks,
			Domains:  group.ExcludedDomains,
		}
		if err := gs.Add(g); err != nil {
			return nil, err
		}
	}
	return gs, nil
}

func dnsPacketsToQueries(packets []*dns.Packet) *client.QueriesRequest {
	qr := client.NewQueriesRequest()
	for i := range packets {
		qr.AddQuery(packets[i].ToRequestQuery())
	}
	return qr
}
