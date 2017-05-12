// Package executor execs main loop in namescore
package executor

import (
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
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
	groups, err := createGroups(cfg)
	if err != nil {
		return nil, err
	}

	eventsLogger, err := events.NewJSONFileLogger(cfg.Events.File)
	if err != nil {
		return nil, err
	}

	eventsPoller := events.NewPoller(c, eventsLogger)
	if err = eventsPoller.SetFollowDataFile(cfg.Data.File); err != nil {
		return nil, err
	}

	return &Executor{
		c:            c,
		cfg:          cfg,
		eventsLogger: eventsLogger,
		eventsPoller: eventsPoller,
		groups:       groups,
		buf:          dns.NewPacketBuffer(),
	}, nil
}

func (e *Executor) Start() error {
	log.Infof("creating sniffer for %s interface, port %d, protocols %v",
		e.cfg.Network.Interface, e.cfg.Network.Port, e.cfg.Network.Protocols)
	sniffer, err := dns.NewLiveSniffer(e.cfg.Network.Interface, e.cfg.Network.Protocols, e.cfg.Network.Port)
	if err != nil {
		return err
	}
	e.sniffer = sniffer
	e.sniffer.SetGroups(e.groups)

	if e.cfg.Queries.Failed.File != "" {
		if e.dnsWriter, err = dns.NewWriter(e.cfg.Queries.Failed.File); err != nil {
			return err
		}
	}

	go e.startEventPoller(e.cfg.Events.PollInterval, e.cfg.Events.File, e.cfg.Data.File)
	go e.startPacketSender(e.cfg.Queries.FlushInterval)

	return e.do()
}

func (e *Executor) StartOffline() error {
	log.Infof("creating offline sniffer for %s interface, port %d, protocols %v",
		e.cfg.Network.Interface, e.cfg.Network.Port, e.cfg.Network.Protocols)
	sniffer, err := dns.NewLiveSniffer(e.cfg.Network.Interface, e.cfg.Network.Protocols, e.cfg.Network.Port)
	if err != nil {
		return err
	}
	e.sniffer = sniffer
	e.sniffer.SetGroups(e.groups)

	if e.cfg.Queries.Failed.File != "" {
		if e.dnsWriter, err = dns.NewWriter(e.cfg.Queries.Failed.File); err != nil {
			return err
		}
	}

	go e.startPacketWriter(e.cfg.Queries.FlushInterval)

	return e.do()
}

func (e *Executor) Send(file string) error {
	log.Infof("creating sniffer for %s file", file)
	sniffer, err := dns.NewOfflineSniffer(file, e.cfg.Network.Protocols, e.cfg.Network.Port)
	if err != nil {
		return err
	}
	e.sniffer = sniffer
	e.sniffer.SetGroups(e.groups)

	return e.do()
}

func (e *Executor) startEventPoller(interval time.Duration, logFile, dataFile string) {
	// event poller will return error from api or
	// wrinting to disk. In both cases log the error
	// and try again in a moment.
	for {
		if err := e.eventsPoller.Do(interval); err != nil {
			log.Errorln(err)
		}
	}
}

func (e *Executor) startPacketSender(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		e.sendPackets()
	}
}

func (e *Executor) startPacketWriter(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		if e.dnsWriter != nil {
			if err := e.dnsWriter.Write(e.buf.Packets()); err != nil {
				log.Warnln(err)
				continue
			} else {
				log.Infof("%d queries wrote to file", len(e.buf.Packets()))
			}
		} else if len(e.buf.Packets()) > 0 {
			log.Infof("no queries failed file set, %d queries will be discarded", len(e.buf.Packets()))
		}
		e.buf.Reset()
	}
}

func (e *Executor) sendPackets() {
	e.mx.Lock()
	defer e.mx.Unlock()

	packets := e.buf.Packets()
	if len(packets) == 0 {
		return
	}

	log.Infof("sending %d packets to analyze", len(packets))
	if _, err := e.c.Queries(dnsPacketsToQueries(packets)); err != nil {
		log.Errorln(err)

		if e.dnsWriter != nil {
			// try to write packets to file. If success then resset
			// buffer, else keep in buffer and try in a moment.
			if err := e.dnsWriter.Write(packets); err != nil {
				log.Warnln(err)
			} else {
				log.Infof("%d queries wrote to file", len(e.buf.Packets()))
			}
		}
	}
	// all packets sent, reset buffer
	e.buf.Reset()
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
	if len(cfg.WhiteListConfig.Groups) == 0 {
		return nil, nil
	}

	log.Infof("creating groups")
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
