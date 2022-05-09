// Package executor execs main loop in nfr
package executor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/alphasoc/nfr/alerts"
	"github.com/alphasoc/nfr/client"
	"github.com/alphasoc/nfr/config"
	"github.com/alphasoc/nfr/elastic"
	"github.com/alphasoc/nfr/groups"
	"github.com/alphasoc/nfr/logs"
	"github.com/alphasoc/nfr/logs/bro"
	"github.com/alphasoc/nfr/logs/edge"
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

	httpbuf    *packet.HTTPPacketBuffer
	httpWriter *packet.Writer

	sniffer sniffer.Sniffer
	lr      logs.FileParser

	// mutex for synchronize sending packets.
	mx sync.Mutex
}

func getFormatter(format string) alerts.Formatter {
	var f alerts.Formatter

	switch format {
	case "json":
		f = alerts.FormatterJSON{}
	case "cef":
		f = alerts.NewFormatterCEF()
	}

	return f
}

// New creates new executor.
func New(c client.Client, cfg *config.Config) (*Executor, error) {
	e := &Executor{
		c:   c,
		cfg: cfg,
	}

	groups, err := createGroups(cfg)
	if err != nil {
		return nil, err
	}
	e.groups = groups

	if cfg.HasOutputs() {
		log.Info("outputs enabled")
		mapper := alerts.NewAlertMapper(groups)
		e.alertsPoller = alerts.NewPoller(c, mapper)
		if err := e.alertsPoller.SetFollowDataFile(cfg.Data.File); err != nil {
			return nil, err
		}

		if cfg.Outputs.File != "" {
			format := getFormatter(cfg.Outputs.Format)
			if format == nil {
				return nil, fmt.Errorf("invalid output format: %s", cfg.Outputs.Format)
			}

			fileWriter, err := alerts.NewFileWriter(cfg.Outputs.File, format)

			if err != nil {
				return nil, err
			}
			e.alertsPoller.AddWriter(fileWriter)
		}

		if cfg.Outputs.Graylog.URI != "" {
			graylogWriter, err := alerts.NewGraylogWriter(cfg.Outputs.Graylog.URI, cfg.Outputs.Graylog.Level)
			if err != nil {
				return nil, err
			}
			e.alertsPoller.AddNetWriter(graylogWriter)
		}

		if cfg.Outputs.Syslog.IP != "" {
			addr := net.JoinHostPort(cfg.Outputs.Syslog.IP, strconv.FormatInt(int64(cfg.Outputs.Syslog.Port), 10))
			format := getFormatter(cfg.Outputs.Syslog.Format)
			if format == nil {
				return nil, fmt.Errorf("invalid syslog format: %s", cfg.Outputs.Syslog.Format)
			}

			syslogWriter, err := alerts.NewSyslogWriter(cfg.Outputs.Syslog.Proto, addr, format)
			if err != nil {
				return nil, err
			}
			e.alertsPoller.AddNetWriter(syslogWriter)
		}
	}

	e.dnsbuf = packet.NewDNSPacketBuffer()
	e.ipbuf = packet.NewIPPacketBuffer()
	e.httpbuf = packet.NewHTTPPacketBuffer()
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
			log.Infof("creating the network sniffer on %s", e.cfg.Inputs.Sniffer.Interface)
			e.sniffer, err = sniffer.NewLivePcapSniffer(e.cfg.Inputs.Sniffer.Interface, &sniffer.Config{
				BPFilter: "tcp or udp",
			})
			if err != nil {
				return fmt.Errorf("can't create the network sniffer: %s", err)
			}
			log.Infof("starting the network sniffer on %s", e.cfg.Inputs.Sniffer.Interface)
			e.do()
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	if e.cfg.Inputs.Elastic.Enabled {
		e.startElastic(ctx, wg)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	cancel()
	wg.Wait()

	return nil
}

func (e *Executor) startElastic(ctx context.Context, wg *sync.WaitGroup) error {
	cfg := &e.cfg.Inputs.Elastic
	for searchIdx, search := range cfg.Searches {
		c, err := elastic.NewClient(cfg)
		if err != nil {
			return err
		}

		wg.Add(1)
		go func(idx int, c *elastic.Client, search *elastic.SearchConfig) {
			defer wg.Done()

			asoclient := client.New(e.cfg.Engine.Host, e.cfg.Engine.APIKey)
			log := log.WithField("name", fmt.Sprintf("%v-%03d", search.EventType, idx))
			checkpointFname := "elastic-" + elastic.ConfigFingerprint(cfg, search)

			// Load last es search checkpoint.
			lastIngested := e.cfg.LoadTimestamp(checkpointFname, 24*time.Hour)

			// We want the ticker to fire immediately once, and then with the configured
			// search poll interval.
			ticker := time.NewTicker(100 * time.Millisecond)
			firstTick := true

			for {
				select {
				case <-ctx.Done():
					log.Infof("client done")
					return
				case <-ticker.C:
					log.Debugf("processing %v search", search.EventType)

					if firstTick {
						firstTick = false
						ticker.Reset(time.Duration(search.PollInterval) * time.Second)
					}

					lctx := context.Background()
					cur, err := c.Fetch(lctx, search, lastIngested)
					if err != nil {
						log.Errorf("es query failed: %v", err)
						continue
					}

					firstSearchPage := true
					for {
						hits, err := cur.Next(lctx)

						if e.cfg.Log.Level == "debug" {
							fname := "elastic-" + elastic.ConfigFingerprint(cfg, search) + "-search"
							fullname := path.Join(e.cfg.Data.Dir, fname)
							if err := cur.DumpLastSearchQuery(fullname); err != nil {
								log.Debugf("error saving last search query: %v", err)
							} else {
								log.Debugf("recent search query saved to %v", fullname)
							}
						}

						if err != nil {
							log.Errorf("fetch events: %v", err)
							break
						}

						if len(hits) == 0 {
							if firstSearchPage {
								log.Info("search has returned no results")
							}
							// No more pages.
							break
						}

						firstSearchPage = false

						switch search.EventType {
						case client.EventTypeDNS:
							// Convert []elastic.Hit to client.EventsDNSRequest
							req := &client.EventsDNSRequest{}
							for n, h := range hits {
								entry, err := h.DecodeDNS(search)
								if err != nil {
									log.Debugf("failed to decode dns event: %v", err)
									continue
								}

								if e.cfg.Log.Level == "debug" && n < 5 {
									log.Debugf("event: %+v", entry)
								}

								if _, ok := e.groups.IsDNSQueryWhitelisted(entry.Query, entry.SrcIP, nil); ok {
									req.Entries = append(req.Entries, entry)
								}
							}

							// Send events to the API
							inglog := log.WithField("lastIngested", cur.NewestIngested())
							if len(req.Entries) > 0 {
								resp, err := asoclient.EventsDNS(req)
								if err != nil {
									log.Errorf("sending dns events: %v", err)
									continue
								}
								inglog.WithField("events", resp.Accepted).Info("telemetry sent")
							} else {
								inglog.WithField("retrievedEvents", len(hits)).Info("no retrieved events in scope")
							}

						case client.EventTypeIP:
							req := &client.EventsIPRequest{}
							for n, h := range hits {
								entry, err := h.DecodeIP(search)
								if err != nil {
									log.Debugf("failed to decode ip event: %v", err)
									continue
								}

								if e.cfg.Log.Level == "debug" && n < 5 {
									log.Debugf("event: %+v", entry)
								}

								if _, ok := e.groups.IsIPWhitelisted(entry.SrcIP, entry.DstIP); ok {
									req.Entries = append(req.Entries, entry)
								}
							}

							// Send events to the API
							inglog := log.WithField("lastIngested", cur.NewestIngested())
							if len(req.Entries) > 0 {
								resp, err := asoclient.EventsIP(req)
								if err != nil {
									log.Errorf("sending dns events: %v", err)
									continue
								}
								inglog.WithField("events", resp.Accepted).Info("telemetry sent")
							} else {
								inglog.WithField("retrievedEvents", len(hits)).Info("no retrieved events in scope")
							}

						case client.EventTypeHTTP:
							var entries []*client.HTTPEntry
							for n, h := range hits {
								entry, err := h.DecodeHTTP(search)
								if err != nil {
									log.Debugf("failed to decode ip event: %v", err)
									continue
								}

								if e.cfg.Log.Level == "debug" && n < 5 {
									log.Debugf("event: %+v", entry)
								}

								if _, ok := e.groups.IsHTTPQueryWhitelisted(entry.URL, entry.SrcIP); ok {
									entries = append(entries, entry)
								}
							}

							// Send events to the API
							inglog := log.WithField("lastIngested", cur.NewestIngested())
							if len(entries) > 0 {
								resp, err := asoclient.EventsHTTP(entries)
								if err != nil {
									log.Errorf("sending dns events: %v", err)
									continue
								}
								inglog.WithField("events", resp.Accepted).Info("telemetry sent")
							} else {
								inglog.WithField("retrievedEvents", len(hits)).Info("no retrieved events in scope")
							}

						case client.EventTypeTLS:
							var entries []*client.TLSEntry
							for n, h := range hits {
								entry, err := h.DecodeTLS(search)
								if err != nil {
									log.Debugf("failed to decode ip event: %v", err)
									continue
								}

								if e.cfg.Log.Level == "debug" && n < 5 {
									log.Debugf("event: %+v", entry)
								}

								if _, ok := e.groups.IsIPWhitelisted(entry.SrcIP, entry.DstIP); ok {
									entries = append(entries, entry)
								}
							}

							// Send events to the API
							inglog := log.WithField("lastIngested", cur.NewestIngested())
							if len(entries) > 0 {
								resp, err := asoclient.EventsTLS(entries)
								if err != nil {
									log.Errorf("sending dns events: %v", err)
									continue
								}
								inglog.WithField("events", resp.Accepted).Info("telemetry sent")
							} else {
								inglog.WithField("retrievedEvents", len(hits)).Info("no retrieved events in scope")
							}
						}

						// Save checkpoint
						t := cur.NewestIngested()
						if err := e.cfg.SaveTimestamp(checkpointFname, t); err != nil {
							log.Errorf("error writing checkpoint: %v", err)
						} else {
							lastIngested = t
						}
					}

					if err := cur.Close(); err != nil {
						log.Warnf("close pit failed: %v", err)
					}
				}
			}
		}(searchIdx, c, search)
	}

	return nil
}

// Send sends dns events from given format file to engine.
func (e *Executor) Send(file, fileFormat, fileType string) error {
	if fileType == "all" {
		for _, ft := range []string{"dns", "ip", "http"} {
			if err := e.sendOne(file, fileFormat, ft); err != nil {
				return err
			}
		}
		return nil
	}

	return e.sendOne(file, fileFormat, fileType)
}

func (e *Executor) sendOne(file, fileFormat, fileType string) error {
	if err := e.openFileParser(file, fileFormat); err != nil {
		return err
	}
	defer e.lr.Close()

	switch fileType {
	case "dns":
		return e.processDNSReader()
	case "ip":
		return e.processIPReader()
	case "http":
		return e.processHTTPReader()
	}

	return errors.New("file type not supported")
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
			Poll:   !e.cfg.Inputs.UseInotify,
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
				p := msdns.NewParser()
				p.TimeFormat = e.cfg.Inputs.MSDNSTimeFormat
				parser = p
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
				case "http":
					if e.cfg.Engine.Analyze.HTTP {
						dnspacket, err := parser.ParseLineHTTP(line.Text)
						if err != nil {
							log.Errorf("file %s: %s", monitor.File, err)
							continue
						}

						// some formats have metadata and it returns no error and no packet either
						if dnspacket == nil {
							continue
						}

						if !e.shouldSendHTTPPacket(dnspacket) {
							continue
						}
						e.mx.Lock()
						e.httpbuf.Write(dnspacket)
						l := e.httpbuf.Len()
						e.mx.Unlock()
						if l >= e.cfg.HTTPEvents.BufferSize {
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

func (e *Executor) processHTTPReader() error {
	if !e.cfg.Engine.Analyze.HTTP {
		log.Warn("http events processing disabled")
		return nil
	}

	httppackets, err := e.lr.ReadHTTP()
	if err != nil {
		return err
	}
	log.Infof("found %d http packets", len(httppackets))

	for _, httppacket := range httppackets {
		if !e.shouldSendHTTPPacket(httppacket) {
			continue
		}

		e.httpbuf.Write(httppacket)
		if e.httpbuf.Len() >= e.cfg.HTTPEvents.BufferSize {
			if err := e.sendHTTPPackets(); err != nil {
				return err
			}
		}
	}

	return e.sendHTTPPackets()
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

	if e.cfg.Engine.Analyze.HTTP {
		go func() {
			for range time.NewTicker(e.cfg.HTTPEvents.FlushInterval).C {
				e.sendHTTPPackets()
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

// sendHTTPPackets sends http packets to api.
func (e *Executor) sendHTTPPackets() error {
	// retrive copy of packet and reset the buffer
	e.mx.Lock()
	packets := e.httpbuf.Packets()
	e.mx.Unlock()

	if len(packets) == 0 {
		return nil
	}

	log.Infof("sending %d http events for analysis", len(packets))
	resp, err := e.c.EventsHTTP(packets)
	if err != nil {
		log.Errorf("sending %d http events for analysis failed: %s", len(packets), err)

		// write unsaved packets back to buffer
		e.mx.Lock()
		e.httpbuf.Write(packets...)
		e.mx.Unlock()
		return err
	}

	log.Infof("%d of %d total http events were successfully sent for analysis", resp.Accepted, resp.Received)
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

func (e *Executor) shouldSendHTTPPacket(p *client.HTTPEntry) bool {
	// no scope groups configured
	if e.groups == nil {
		return true
	}

	name, t := e.groups.IsHTTPQueryWhitelisted(p.URL, p.SrcIP)
	if !t {
		log.Debugf("http query from %s to %s excluded by %s group", p.SrcIP, p.URL, name)
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
			Label:           group.Label,
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
		var p *msdns.Parser
		p, err = msdns.NewFileParser(file)
		if p != nil {
			p.TimeFormat = e.cfg.Inputs.MSDNSTimeFormat
		}
		e.lr = p
	case "syslog-named":
		e.lr, err = syslognamed.NewFileParser(file)
	case "edge":
		e.lr, err = edge.NewFileParser(file)
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
			Ja3:       ippacket.Ja3,
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
