package cmd

import (
	"os"
	"time"

	"github.com/alphasoc/namescore/asoc"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/dns"
	log "github.com/inconshreveable/log15"
)

type listenHandler struct {
	logger     log.Logger
	client     asoc.AlphaSOCAPI
	queryStore *asoc.QueryStore
	sniffer    dns.Capture
	cfg        *config.Config
	quit       chan bool
	queries    chan []asoc.Entry
}

func (l *listenHandler) getAlerts() {
	l.logger.Debug("Getting alerts.")
	status, err := l.client.AccountStatus()
	if err != nil {
		l.logger.Warn("Failed to check account status", "err", err)
		return
	}
	if status.Expired || !status.Registered {
		l.logger.Warn("Account status is expired or not registered")
		for _, msg := range status.Messages {
			l.logger.Warn("Server response:", "msg", msg.Body)
		}
		return
	}

	follow, err := asoc.ReadFollow(l.cfg.FollowFilePath)
	if err != nil {
		l.logger.Warn("Failed to read follow", "err", err)
		return
	}

	events, errEvents := l.client.Events(follow)
	if errEvents != nil {
		l.logger.Warn("Failed to retrieve events", "err", errEvents)
		return
	}

	if errStore := asoc.StoreAlerts(l.cfg.AlertFilePath, events.Strings()); errStore != nil {
		l.logger.Warn("Failed to store alerts", "error", errStore)
		return
	}
	if errWrite := asoc.WriteFollow(l.cfg.FollowFilePath, events.Follow); errWrite != nil {
		l.logger.Warn("Failed to update follow", "error", errWrite)
		return
	}
	l.logger.Debug("Events were collected, alerts if any were stored, follow was updated.")
}

func (l *listenHandler) AlertsLoop() {
	timer := time.NewTicker(l.cfg.AlertRequestInterval)
	for {
		select {
		case <-timer.C:
			l.getAlerts()
		case <-l.quit:
			timer.Stop()
			l.logger.Info("Stopped retrieving alerts.")
			return
		}
	}
}

func (l *listenHandler) QueriesLoop() {
	for {
		select {
		case senddata := <-l.queries:
			go l.sendQueries(senddata)
		case <-l.quit:
			l.logger.Info("Stopped sending queries.")
			return
		}
	}
}

func (l *listenHandler) sendQueries(data []asoc.Entry) {
	l.logger.Debug("Sending queries.")
	if len(data) == 0 {
		return
	}
	request := &asoc.QueriesReq{Data: data}
	resp, err := l.client.Queries(request)

	if err != nil {
		l.logger.Warn("Sending queries failed.", "err", err)
		if errStore := l.queryStore.Store(request); errStore != nil {
			l.logger.Warn("Storing queries failed.", "err", errStore)
		}
		return
	}
	if resp.Accepted*9 <= resp.Received {
		l.logger.Warn("Queries bad acceptance rate detected.", "received", resp.Received, "accepted", resp.Accepted)
	}
	l.logger.Debug("Queries were successfully send.", "received", resp.Received, "accepted", resp.Accepted)
}

func (l *listenHandler) LocalQueriesLoop() {
	timer := time.NewTicker(l.cfg.LocalQueriesInterval)
	for {
		select {
		case <-timer.C:
			l.localQueries()
		case <-l.quit:
			timer.Stop()
			l.logger.Info("Stopped sending queries.")
			return
		}
	}
}

func (l *listenHandler) localQueries() {
	files, err := l.queryStore.GetQueryFiles()
	if err != nil {
		l.logger.Warn("Searching for local queries failed.", "err", err)
	}
	l.logger.Debug("Local queries scan", "found", len(files))
	for _, file := range files {
		query, err := l.queryStore.Read(file)
		if err != nil {
			l.logger.Warn("Reading queries failed.", "file", file, "err", err)
			if err = os.Remove(file); err != nil {
				l.logger.Warn("Removing queries failed.", "file", file, "err", err)
			}
			continue
		}
		resp, err := l.client.Queries(query)
		if err != nil {
			continue
		}
		if resp.Accepted*9 <= resp.Received {
			l.logger.Warn("Queries bad acceptance rate detected.", "received", resp.Received, "accepted", resp.Accepted)
		}
		if err = os.Remove(file); err != nil {
			l.logger.Warn("Removing queries failed.", "file", file, "err", err)
		}
	}

}

func (l *listenHandler) SniffLoop() {
	l.queries = make(chan []asoc.Entry, 10)
	var buffer []asoc.Entry
	timer := time.NewTicker(l.cfg.LocalQueriesInterval)
	for {
		select {
		case <-timer.C:
			l.queries <- buffer
			buffer = nil
		case <-l.quit:
			l.sniffer.Close()
			timer.Stop()
			return
		default:
			entries := l.sniffer.PacketToEntry(l.sniffer.Sniff())
			if len(entries) == 0 {
				continue
			}
			l.logger.Debug("Sniffed:", "FQDN", entries[0].FQDN, "IP", entries[0].IP.String())
			buffer = append(buffer, entries...)
			if len(buffer) >= l.cfg.SendIntervalAmount {
				l.queries <- buffer
				buffer = nil
			}
		}
	}
}
