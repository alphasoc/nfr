package cmd

import (
	"os"
	"time"

	"github.com/alphasoc/namescore/internal/asoc"
	"github.com/alphasoc/namescore/internal/config"
	"github.com/alphasoc/namescore/internal/dns"
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

	follow := asoc.ReadFollow(l.cfg.FollowFilePath)
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
}

func (l *listenHandler) AlertsLoop() {
	timer := time.NewTicker(l.cfg.AlertRequestInterval)
	for {
		select {
		case <-timer.C:
			l.logger.Info("QueriesLoop() Notified to check alerts.")
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
			l.logger.Info("QueriesLoop() received queries to send.")
			go l.sendQueries(senddata)
		case <-l.quit:
			l.logger.Info("Stopped sending queries.")
			return
		}
	}
}

func (l *listenHandler) sendQueries(data []asoc.Entry) {
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
	if rate := resp.Received * 100 / resp.Accepted; rate < 90 {
		l.logger.Warn("Queries bad acceptance rate detected.", "received", resp.Received, "accepted", resp.Accepted)
	}
}

func (l *listenHandler) LocalQueriesLoop() {
	timer := time.NewTicker(l.cfg.LocalQueriesInterval)
	for {
		select {
		case <-timer.C:
			l.logger.Debug("LocalQueriesLoop(): Received notification to scan local queries.")
			l.localQueries()
		case <-l.quit:
			timer.Stop()
			l.logger.Info("Stopped sending queries.")
			return
		}
	}
}

func (l *listenHandler) localQueries() {
	files := l.queryStore.GetQueryFiles()
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
		if rate := resp.Received * 100 / resp.Accepted; rate < 90 {
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
			l.logger.Debug("SniffLoop(): received queries notification.")
			l.queries <- buffer
			buffer = nil
		case <-l.quit:
			l.sniffer.Close()
			timer.Stop()
			l.logger.Info("Stopped sending queries.")
			return
		default:
			entries := l.sniffer.PacketToEntry(l.sniffer.Sniff())
			if entries == nil {
				continue
			}
			buffer = append(buffer, entries...)
			if len(buffer) >= l.cfg.SendIntervalAmount {
				l.logger.Debug("SniffLoop(): sending queries to channel.", "size", len(buffer))
				l.queries <- buffer
				buffer = nil
			}
		}
	}
}
