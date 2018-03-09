// Package executor execs main loop in nfr
package executor

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/nfr/alerts"
	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/config"
	"github.com/alphasoc/nfr/groups"
	"github.com/alphasoc/nfr/logs"
	"github.com/alphasoc/nfr/logs/bro"
	"github.com/alphasoc/nfr/logs/msdns"
	"github.com/alphasoc/nfr/logs/pcap"
	"github.com/alphasoc/nfr/logs/suricata"
	"github.com/alphasoc/nfr/packet"
	"github.com/alphasoc/nfr/sniffer"
	"github.com/alphasoc/nfr/utils"
	"github.com/hpcloud/tail"
)

// Executor executes main nfr loop. It's respnsible for start the sniffer,
// send ip/dns events to AlphaSOC Engine and poll alerts from it.
type Executor struct {
	c   client.Client
	cfg *config.Config

	alertsPoller *alerts.Poller

	groups *groups.Groups

	dnsbuf    *packet.DNSPacketBuffer
	dnsWriter *packet.Writer

	ipbuf    *packet.IPPacketBuffer
	ipWriter *packet.Writer

	sniffer sniffer.Sniffer
	lr      logs.FileParser

	// mutex for synchronize sending packets.
	mx sync.Mutex
}

// New creates new executor.
func New(c client.Client, cfg *config.Config) (*Executor, error) {
	groups, err := createGroups(cfg)
	if err != nil {
		return nil, err
	}

	var jsonWriter, graylogWriter alerts.Writer

	if cfg.Alerts.File != "" {
		jsonWriter, err = alerts.NewJSONFileWriter(cfg.Alerts.File)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Alerts.Graylog.URI != "" {
		graylogWriter, err = alerts.NewGraylogWriter(cfg.Alerts.Graylog.URI, cfg.Alerts.Graylog.Level)
		if err != nil {
			return nil, err
		}
	}

	alertsPoller := alerts.NewPoller(c)
	if jsonWriter != nil {
		alertsPoller.AddWriter(jsonWriter)
	}
	if graylogWriter != nil {
		alertsPoller.AddWriter(graylogWriter)
	}
	if err = alertsPoller.SetFollowDataFile(cfg.Data.File); err != nil {
		return nil, err
	}

	return &Executor{
		c:            c,
		cfg:          cfg,
		alertsPoller: alertsPoller,
		groups:       groups,
		dnsbuf:       packet.NewDNSPacketBuffer(),
		ipbuf:        packet.NewIPPacketBuffer(),
	}, nil
}

// Start starts sniffer in online mode, where network alerts are sent to api.
func (e *Executor) Start() (err error) {
	log.Infof("creating sniffer for %s interface", e.cfg.Network.Interface)
	e.sniffer, err = sniffer.NewLivePcapSniffer(e.cfg.Network.Interface, &sniffer.Config{
		EnableDNSAnalitics: e.cfg.Alphasoc.Analyze.DNS,
		EnableIPAnalitics:  e.cfg.Alphasoc.Analyze.IP,
		Protocols:          e.cfg.Network.DNS.Protocols,
		Port:               e.cfg.Network.DNS.Port,
	})
	if err != nil {
		return err
	}

	if e.cfg.DNSEvents.Failed.File != "" {
		if e.dnsWriter, err = packet.NewWriter(e.cfg.DNSEvents.Failed.File); err != nil {
			return fmt.Errorf("can't open file %s for writing dns events: %s", e.cfg.DNSEvents.Failed.File, err.(*net.OpError).Err)
		}
	}
	if e.cfg.IPEvents.Failed.File != "" {
		if e.ipWriter, err = packet.NewWriter(e.cfg.IPEvents.Failed.File); err != nil {
			return fmt.Errorf("can't open file %s for writing ip events: %s", e.cfg.IPEvents.Failed.File, err.(*net.OpError).Err)
		}
	}

	e.init()
	return e.do()
}

// Send sends dns events from given format file to engine.
func (e *Executor) Send(file string, fileFomrat string, fileType string) (err error) {
	switch fileFomrat {
	case "bro":
		e.lr, err = bro.NewFileParser(file)
	case "pcap":
		e.lr, err = pcap.NewReader(file)
	case "suricata":
		e.lr, err = suricata.NewFileParser(file)
	case "msdns":
		e.lr, err = msdns.NewFileParser(file)
	default:
		return errors.New("file format not supported")
	}
	if err != nil {
		return err
	}

	switch fileType {
	case "dns":
		return e.processDNSReader()
	case "ip":
		return e.processIPReader()
	default:
		return errors.New("file type not supported")
	}
}

// Monitor monitors log files and send data to engine.
func (e *Executor) Monitor() error {
	if len(e.cfg.Monitors) == 0 {
		log.Fatalf("no files specify for monitoring")
	}

	e.init()
	for _, monitor := range e.cfg.Monitors {
		t, err := tail.TailFile(monitor.File, tail.Config{
			Follow: true,
			ReOpen: true,
			Logger: log.StandardLogger(),
		})
		if err != nil {
			return err
		}

		go func(monitor config.Monitor) {
			var parser logs.Parser
			switch monitor.Format {
			case "bro":
				parser = bro.NewParser()
			case "suricata":
				parser = suricata.NewParser()
			case "msdns":
				parser = msdns.NewParser()
			}

			for line := range t.Lines {
				switch monitor.Type {
				case "ip":
					ippacket, err := parser.ParseLineIP(line.Text)
					if err != nil {
						log.Errorf("file %s: %s", monitor.File, err)
						continue
					}

					// some formats have metadata and it returns no error and no packet either
					if ippacket == nil {
						continue
					}

					if !e.shouldSendIPPacket(ippacket) {
						continue
					}
					e.ipbuf.Write(ippacket)
				case "dns":
					dnspacket, err := parser.ParseLineDNS(line.Text)
					if err != nil {
						log.Errorf("file %s: %s", monitor.File, err)
						continue
					}

					// some formats have metadata and it returns no error and no packet either
					if dnspacket == nil {
						continue
					}

					if !e.shouldSendDNSPacket(dnspacket) {
						continue
					}
					e.dnsbuf.Write(dnspacket)
				}
			}
		}(monitor)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	return nil
}

// init initialize executor.
func (e *Executor) init() {
	e.installSignalHandler()
	e.startAlertPoller()
	e.startPacketSender()
}

func (e *Executor) processDNSReader() error {
	if !e.cfg.Alphasoc.Analyze.DNS {
		return nil
	}

	dnspackets, err := e.lr.ReadDNS()
	if err != nil {
		return err
	}

	for _, dnspacket := range dnspackets {
		if !e.shouldSendDNSPacket(dnspacket) {
			continue
		}

		e.dnsbuf.Write(dnspacket)
		if e.dnsbuf.Len() >= e.cfg.DNSEvents.BufferSize {
			if err := e.sendDNSPackets(); err != nil {
				return err
			}
		}
	}
	return e.sendDNSPackets()
}

func (e *Executor) processIPReader() error {
	if !e.cfg.Alphasoc.Analyze.IP {
		return nil
	}

	ippackets, err := e.lr.ReadIP()
	if err != nil {
		return err
	}

	for _, ippacket := range ippackets {
		if !e.shouldSendIPPacket(ippacket) {
			continue
		}

		e.ipbuf.Write(ippacket)
		if e.ipbuf.Len() >= e.cfg.IPEvents.BufferSize {
			if err := e.sendIPPackets(); err != nil {
				return err
			}
		}
	}
	return e.sendIPPackets()
}

// startPacketSender periodcly send dns and ip packets to api.
func (e *Executor) startPacketSender() {
	if e.cfg.Alphasoc.Analyze.DNS {
		go func() {
			for range time.NewTicker(e.cfg.DNSEvents.FlushInterval).C {
				e.sendDNSPackets()
			}
		}()
	}

	if e.cfg.Alphasoc.Analyze.IP {
		go func() {
			for range time.NewTicker(e.cfg.IPEvents.FlushInterval).C {
				e.sendIPPackets()
			}
		}()
	}
}

// sendDNSPackets sends dns packets to api.
func (e *Executor) sendDNSPackets() error {
	// retrive copy of packet and reset the buffer
	e.mx.Lock()
	packets := e.dnsbuf.Packets()
	e.mx.Unlock()

	if len(packets) == 0 {
		return nil
	}

	log.Infof("sending %d dns events to analyze", len(packets))
	resp, err := e.c.EventsDNS(dnsPacketsToRequest(packets))
	if err != nil {
		log.Errorln(err)

		// write unsaved packets back to buffer
		e.mx.Lock()
		e.dnsbuf.Write(packets...)
		e.mx.Unlock()
		return err
	}

	if resp.Received == resp.Accepted {
		log.Infof("%d dns events were successfully send", resp.Accepted)
	} else {
		log.Infof("%d of %d dns events were send - rejected reason %v",
			resp.Accepted, resp.Received, resp.Rejected)
	}
	return nil
}

// sendIPPackets sends ip packets to api.
func (e *Executor) sendIPPackets() error {
	// retrive copy of packet and reset the buffer
	e.mx.Lock()
	packets := e.ipbuf.Packets()
	e.mx.Unlock()

	if len(packets) == 0 {
		return nil
	}

	log.Infof("sending %d ip events to analyze", len(packets))
	resp, err := e.c.EventsIP(ipPacketsToRequest(packets))
	if err != nil {
		log.Errorln(err)

		// write unsaved packets back to buffer
		e.mx.Lock()
		e.ipbuf.Write(packets...)
		e.mx.Unlock()
		return err
	}

	if resp.Received == resp.Accepted {
		log.Infof("%d ip events were successfully send", resp.Accepted)
	} else {
		log.Infof("%d of %d ip events were send - rejected reason %v",
			resp.Accepted, resp.Received, resp.Rejected)
	}
	return nil
}

// do retrives packets from sniffer, filter it and send to api.
func (e *Executor) do() error {
	for rawpacket := range e.sniffer.Packets() {
		if e.cfg.Alphasoc.Analyze.IP {
			ippacket := packet.NewIPPacket(rawpacket)
			if ippacket == nil {
				// continue because if packet isn't ip packet, then it can't be dns packet
				continue
			}
			ippacket.DetermineDirection(e.cfg.Network.HardwareAddr)

			if e.shouldSendIPPacket(ippacket) {
				e.mx.Lock()
				e.ipbuf.Write(ippacket)
				l := e.ipbuf.Len()
				e.mx.Unlock()
				if l >= e.cfg.IPEvents.BufferSize {
					go e.sendIPPackets()
				}
			}
		}

		if e.cfg.Alphasoc.Analyze.DNS {
			dnspacket := packet.NewDNSPacket(rawpacket)
			if dnspacket == nil {
				continue
			}

			if e.shouldSendDNSPacket(dnspacket) {
				e.mx.Lock()
				e.dnsbuf.Write(dnspacket)
				l := e.dnsbuf.Len()
				e.mx.Unlock()
				if l >= e.cfg.DNSEvents.BufferSize {
					// do not wait for sending packets
					go e.sendDNSPackets()
				}
			}
		}
	}

	// send what left in the buffer
	// and wait for other gorutines to finish
	// thanks to mutex lock in sendDNSPackets
	e.sendDNSPackets()
	e.sendIPPackets()
	return nil
}

// shouldSendIPPacket testdns if ip packet should be send to channel
func (e *Executor) shouldSendIPPacket(p *packet.IPPacket) bool {
	if (p.Direction == packet.DirectionOut && utils.IsSpecialIP(p.DstIP)) ||
		(p.Direction == packet.DirectionIn && utils.IsSpecialIP(p.SrcIP)) {
		return false
	}
	return true
}

// shouldSendDNSPackets tests if dns packet should be send to channel
func (e *Executor) shouldSendDNSPacket(p *packet.DNSPacket) bool {
	if e.cfg.Network.DNS.Port != 0 && e.cfg.Network.DNS.Port != p.DstPort {
		return false
	}
	if !utils.StringsContains(e.cfg.Network.DNS.Protocols, p.Protocol) {
		return false
	}

	// no scope groups configured
	if e.groups == nil {
		return true
	}
	name, t := e.groups.IsDNSQueryWhitelisted(p.FQDN, p.SrcIP)
	if !t {
		log.Debugf("dns query %s excluded by %s group", p, name)
	}
	return t
}

// startAlertPoller periodcly checks for new alerts.
func (e *Executor) startAlertPoller() {
	// event poller will return error on api call or writing to disk.
	// In both cases log the error and try again in a moment.
	go func() {
		for {
			if err := e.alertsPoller.Do(e.cfg.Alerts.PollInterval); err != nil {
				log.Errorln(err)
			}
		}
	}()
}

// installSignalHandler install os.Interrupt handler
// for writing network alerts into file if there some in the buffer.
// If the dns writer is not configured, signal handler
// is not installed.
func (e *Executor) installSignalHandler() {
	// Unless writer is set, then no handler is needed
	if e.dnsWriter == nil && e.ipWriter == nil {
		return
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c

		dnspackets := e.dnsbuf.Packets()
		if e.dnsWriter != nil && len(dnspackets) > 0 {
			for i := range dnspackets {
				if err := e.dnsWriter.Write(dnspackets[i]); err != nil {
					log.Warnln(err)
					break
				}
			}

			log.Infof("%d dns events wrote to file", len(dnspackets))
		}

		ippackets := e.ipbuf.Packets()
		if e.ipWriter != nil && len(ippackets) > 0 {
			for i := range ippackets {
				if err := e.ipWriter.Write(ippackets[i]); err != nil {
					log.Warnln(err)
					break
				}
			}

			log.Infof("%d ip events wrote to file", len(ippackets))
		}

		os.Exit(1)
	}()
}

// createGroups creates groups for matching dns packets.
func createGroups(cfg *config.Config) (*groups.Groups, error) {
	if len(cfg.ScopeConfig.Groups) == 0 {
		return nil, nil
	}

	log.Infof("found %d whiltelist groups", len(cfg.ScopeConfig.Groups))
	gs := groups.New()
	for name, group := range cfg.ScopeConfig.Groups {
		g := &groups.Group{
			Name:     name,
			Includes: group.Networks,
			Excludes: group.Exclude.Networks,
			Domains:  group.Exclude.Domains,
		}
		if err := gs.Add(g); err != nil {
			return nil, err
		}
	}
	return gs, nil
}

// ipPacketsToRequest changes ip packets to client ip request.
func ipPacketsToRequest(packets []*packet.IPPacket) *client.EventsIPRequest {
	var req client.EventsIPRequest
	for _, ippacket := range packets {
		entry := &client.IPEntry{
			Timestamp: ippacket.Timestamp,
			SrcIP:     ippacket.SrcIP,
			SrcPort:   ippacket.SrcPort,
			DestIP:    ippacket.DstIP,
			DestPort:  ippacket.DstPort,
			Protocol:  ippacket.Protocol,
		}
		switch ippacket.Direction {
		case packet.DirectionIn:
			entry.BytesIn = ippacket.BytesCount
		case packet.DirectionOut:
			entry.BytesOut = ippacket.BytesCount
		default:
			continue
		}
		req.Entries = append(req.Entries, entry)
	}
	return &req
}

// dnsPacketsToRequest changes dns packets to client dns request.
func dnsPacketsToRequest(packets []*packet.DNSPacket) *client.EventsDNSRequest {
	var req client.EventsDNSRequest
	for _, dnspacket := range packets {
		req.Entries = append(req.Entries, &client.DNSEntry{
			Timestamp: dnspacket.Timestamp,
			SrcIP:     dnspacket.SrcIP,
			Query:     dnspacket.FQDN,
			QType:     dnspacket.RecordType,
		})
	}
	return &req
}
