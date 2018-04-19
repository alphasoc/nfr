// Package executor execs main loop in nfr
package executor

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
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
	"github.com/alphasoc/nfr/logs/syslognamed"
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
	e := &Executor{
		c:   c,
		cfg: cfg,
	}

	if cfg.HasOutputs() {
		e.alertsPoller = alerts.NewPoller(c)
		if err := e.alertsPoller.SetFollowDataFile(cfg.Data.File); err != nil {
			return nil, err
		}

		if cfg.Outputs.File != "" {
			jsonWriter, err := alerts.NewJSONFileWriter(cfg.Outputs.File)
			if err != nil {
				return nil, err
			}
			e.alertsPoller.AddWriter(jsonWriter)
		}

		if cfg.Outputs.Graylog.URI != "" {
			graylogWriter, err := alerts.NewGraylogWriter(cfg.Outputs.Graylog.URI, cfg.Outputs.Graylog.Level)
			if err != nil {
				return nil, err
			}
			e.alertsPoller.AddWriter(graylogWriter)
		}

		if cfg.Outputs.Syslog.IP != "" {
			addr := net.JoinHostPort(cfg.Outputs.Syslog.IP, strconv.FormatInt(int64(cfg.Outputs.Syslog.Port), 10))
			syslogWriter, err := alerts.NewSyslogWriter(addr)
			if err != nil {
				return nil, err
			}
			e.alertsPoller.AddWriter(syslogWriter)
		}
	}

	e.dnsbuf = packet.NewDNSPacketBuffer()
	e.ipbuf = packet.NewIPPacketBuffer()
	groups, err := createGroups(cfg)
	if err != nil {
		return nil, err
	}
	e.groups = groups

	return e, nil
}

// Start starts sniffer in online mode, where network alerts are sent to api.
func (e *Executor) Start() (err error) {
	e.init()
	if e.cfg.Engine.Analyze.DNS || e.cfg.Engine.Analyze.IP {
		e.monitor()

		if e.cfg.Inputs.Sniffer.Enabled {
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
			e.sniffer, err = sniffer.NewLivePcapSniffer(e.cfg.Inputs.Sniffer.Interface, &sniffer.Config{
				BPFilter: "tcp or udp",
			})
			if err != nil {
				return fmt.Errorf("can't create sniffer: %s", err)
			}
			log.Infof("starting the network sniffer on %s", e.cfg.Inputs.Sniffer.Interface)
			e.do()
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	return nil
}

// Send sends dns events from given format file to engine.
func (e *Executor) Send(file, fileFomrat, fileType string) (err error) {
	if err = e.openFileParser(file, fileFomrat); err != nil {
		return err
	}

	switch fileType {
	case "all":
		if err = e.processIPReader(); err != nil {
			return err
		}

		// some parser cannot be reset, thus they need to be reopen,
		// but first close previous one
		e.lr.Close()
		if err = e.openFileParser(file, fileFomrat); err != nil {
			return err
		}

		err = e.processDNSReader()
	case "dns":
		err = e.processDNSReader()
	case "ip":
		err = e.processIPReader()
	default:
		return errors.New("file type not supported")
	}
	e.lr.Close()
	return err
}

// monitor monitors log files and send data to engine.
func (e *Executor) monitor() {
	for _, monitor := range e.cfg.Inputs.Monitors {
		// skip empty items
		if monitor.File == "" && monitor.Type == "" && monitor.Format == "" {
			continue
		}

		t, err := tail.TailFile(monitor.File, tail.Config{
			Follow: true,
			ReOpen: true,
			Logger: log.StandardLogger(),
		})
		if err != nil {
			log.Errorf("can't caputre log file %s: %s", monitor.File, err)
			continue
		}
		log.Infof("monitoring %s", monitor.File)

		go func(monitor config.Monitor) {
			var parser logs.Parser
			switch monitor.Format {
			case "bro":
				parser = bro.NewParser()
			case "suricata":
				parser = suricata.NewParser()
			case "msdns":
				parser = msdns.NewParser()
			case "syslog-named":
				parser = syslognamed.NewParser()
			}

			for line := range t.Lines {
				switch monitor.Type {
				case "ip":
					if e.cfg.Engine.Analyze.IP {
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

						e.mx.Lock()
						e.ipbuf.Write(ippacket)
						l := e.ipbuf.Len()
						e.mx.Unlock()
						if l >= e.cfg.IPEvents.BufferSize {
							go e.sendIPPackets()
						}
					}
				case "dns":
					if e.cfg.Engine.Analyze.DNS {
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
		}(monitor)
	}
}

// init initialize executor.
func (e *Executor) init() {
	e.installSignalHandler()
	if e.cfg.HasOutputs() {
		e.startAlertPoller()
	}
	if e.cfg.HasInputs() {
		e.startPacketSender()
	}
}

func (e *Executor) processDNSReader() error {
	if !e.cfg.Engine.Analyze.DNS {
		log.Warn("dns events processing disabled")
		return nil
	}

	dnspackets, err := e.lr.ReadDNS()
	if err != nil {
		return err
	}
	log.Infof("found %d dns packets", len(dnspackets))

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
	if !e.cfg.Engine.Analyze.IP {
		log.Warn("ip events processing disabled")
		return nil
	}

	ippackets, err := e.lr.ReadIP()
	if err != nil {
		return err
	}
	log.Infof("found %d ip packets", len(ippackets))

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
	if e.cfg.Engine.Analyze.DNS {
		go func() {
			for range time.NewTicker(e.cfg.DNSEvents.FlushInterval).C {
				e.sendDNSPackets()
			}
		}()
	}

	if e.cfg.Engine.Analyze.IP {
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

	log.Infof("sending %d dns events for analysis", len(packets))
	resp, err := e.c.EventsDNS(dnsPacketsToRequest(packets))
	if err != nil {
		log.Errorf("sending of %d dns events for analysis failed: %s", len(packets), err)

		// write unsaved packets back to buffer
		e.mx.Lock()
		e.dnsbuf.Write(packets...)
		e.mx.Unlock()
		return err
	}

	log.Infof("%d of %d total dns events were successfully sent for analysis", resp.Accepted, resp.Received)
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

	log.Infof("sending %d ip events for analysis", len(packets))
	resp, err := e.c.EventsIP(ipPacketsToRequest(packets))
	if err != nil {
		log.Errorf("sending %d ip events for analysis failed: %s", len(packets), err)

		// write unsaved packets back to buffer
		e.mx.Lock()
		e.ipbuf.Write(packets...)
		e.mx.Unlock()
		return err
	}

	log.Infof("%d of %d total ip events were successfully sent for analysis", resp.Accepted, resp.Received)
	return nil
}

// do retrives packets from sniffer, filter it and send to api.
func (e *Executor) do() error {
	for rawpacket := range e.sniffer.Packets() {
		if e.cfg.Engine.Analyze.IP {
			ippacket := packet.NewIPPacket(rawpacket)
			if ippacket == nil {
				continue
			}

			ippacket.DetermineDirection(e.cfg.Inputs.Sniffer.HardwareAddr)

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

		if e.cfg.Engine.Analyze.DNS {
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

	// send what left in the buffer and
	// wait for other gorutines to finish
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
	// no scope groups configured
	if e.groups == nil {
		return true
	}
	name, t := e.groups.IsIPWhitelisted(p.SrcIP, p.DstIP)
	if !t {
		log.Debugf("ip packet from %s to %s excluded by %s group", p.SrcIP, p.DstIP, name)
	}
	return t
}

// shouldSendDNSPackets tests if dns packet should be send to channel
func (e *Executor) shouldSendDNSPacket(p *packet.DNSPacket) bool {
	// no scope groups configured
	if e.groups == nil {
		return true
	}

	// do not consider to what server dns packets was sent, thus dst ip == nil
	name, t := e.groups.IsDNSQueryWhitelisted(p.FQDN, p.SrcIP, nil)
	if !t {
		log.Debugf("dns query %s excluded by %s group", p, name)
	}
	return t
}

// startAlertPoller periodcly checks for new alerts.
func (e *Executor) startAlertPoller() {
	log.Info("starting the polling mechanism to check for new alerts")
	// event poller will return error on api call or writing to disk.
	// In both cases log the error and try again in a moment.
	go func() {
		for {
			if err := e.alertsPoller.Do(e.cfg.Engine.Alerts.PollInterval); err != nil {
				log.Errorf("polling alerts failed: %s", err)
			}
		}
	}()
}

// installSignalHandler install os.Interrupt handler for writing alerts
// into file if there are some in the buffer. If the dns/ip writer is
// not configured, signal handler is not installed.
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
					log.Warnf("writing dns events to file failed: %s", err)
					break
				}
			}

			log.Infof("%d dns events written to file", len(dnspackets))
		}

		ippackets := e.ipbuf.Packets()
		if e.ipWriter != nil && len(ippackets) > 0 {
			for i := range ippackets {
				if err := e.ipWriter.Write(ippackets[i]); err != nil {
					log.Warnf("writing ip events to file failed: %s", err)
					break
				}
			}

			log.Infof("%d ip events written to file", len(ippackets))
		}

		os.Exit(1)
	}()
}

// createGroups creates groups for matching packets.
func createGroups(cfg *config.Config) (*groups.Groups, error) {
	log.Infof("loaded %d groups containing monitoring scope data", len(cfg.ScopeConfig.Groups))
	if len(cfg.ScopeConfig.Groups) == 0 {
		return nil, nil
	}
	gr := groups.New()
	for name, group := range cfg.ScopeConfig.Groups {
		g := &groups.Group{
			Name:            name,
			SrcIncludes:     group.InScope,
			SrcExcludes:     group.OutScope,
			DstIncludes:     []string{"0.0.0.0/0", "::/0"},
			DstExcludes:     group.TrustedIps,
			ExcludedDomains: group.TrustedDomains,
		}
		if err := gr.Add(g); err != nil {
			return nil, err
		}
	}
	return gr, nil
}

// openFileParser opens file for parse events.
func (e *Executor) openFileParser(file, fileFomrat string) (err error) {
	switch fileFomrat {
	case "bro":
		e.lr, err = bro.NewFileParser(file)
	case "pcap":
		e.lr, err = pcap.NewReader(file)
	case "suricata":
		e.lr, err = suricata.NewFileParser(file)
	case "msdns":
		e.lr, err = msdns.NewFileParser(file)
	case "syslog-named":
		e.lr, err = syslognamed.NewFileParser(file)
	default:
		err = errors.New("file format not supported")
	}
	return err
}

// ipPacketsToRequest changes ip packets to client ip request.
func ipPacketsToRequest(packets []*packet.IPPacket) *client.EventsIPRequest {
	var req client.EventsIPRequest
	for _, ippacket := range packets {
		entry := &client.IPEntry{
			Timestamp: ippacket.Timestamp,
			SrcIP:     ippacket.SrcIP,
			SrcPort:   ippacket.SrcPort,
			DstIP:     ippacket.DstIP,
			DstPort:   ippacket.DstPort,
			Protocol:  ippacket.Protocol,
		}
		switch ippacket.Direction {
		case packet.DirectionIn:
			entry.BytesIn = ippacket.BytesCount
		case packet.DirectionOut:
			entry.BytesOut = ippacket.BytesCount
		default:
			// If can't be determine the assumie it bytes out
			entry.BytesOut = ippacket.BytesCount
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
