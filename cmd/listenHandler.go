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
	l.logger.Info("Checking account status.")
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

	l.logger.Info("Getting alerts.", "follow", follow)
	events, errEvents := l.client.Events(follow)
	if errEvents != nil {
		l.logger.Warn("Failed to retrieve events", "err", errEvents)
		return
	}
	l.logger.Info("Event succesfully retrieved.", "count", len(events.Events))

	if errStore := asoc.StoreAlerts(l.cfg.AlertFilePath, events.Strings()); errStore != nil {
		l.logger.Warn("Failed to store alerts", "error", errStore)
		return
	}
	if errWrite := asoc.WriteFollow(l.cfg.FollowFilePath, events.Follow); errWrite != nil {
		l.logger.Warn("Failed to update follow", "error", errWrite)
		return
	}
	l.logger.Info("Events were collected, alerts if any were stored, follow was updated.")
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
	var buffer []asoc.Entry
	timer := time.NewTicker(l.cfg.SendIntervalTime)
	for {
		select {
		case <-timer.C:
			l.logger.Info("Sending queries because of timer.", "count", len(buffer))
			go l.sendQueries(buffer)
			buffer = nil
		case senddata := <-l.queries:
			buffer = append(buffer, senddata...)
			if len(buffer) >= l.cfg.SendIntervalAmount {
				go l.sendQueries(buffer)
				buffer = nil
			}
		case <-l.quit:
			timer.Stop()
			l.logger.Info("Stopped sending queries.")
			return
		}
	}
}

func (l *listenHandler) sendQueries(data []asoc.Entry) {
	l.logger.Info("Sending queries.", "amount", len(data))
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
	l.logger.Info("Queries were successfully send.", "received", resp.Received, "accepted", resp.Accepted)
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
	l.logger.Info("Scanned local queries.", "found", len(files))
	for _, file := range files {
		query, err := l.queryStore.Read(file)
		if err != nil {
			l.logger.Warn("Reading queries failed.", "file", file, "err", err)
			if err = os.Remove(file); err != nil {
				l.logger.Warn("Removing queries failed.", "file", file, "err", err)
			}
			continue
		}
		l.logger.Info("Sending local queries.", "amount", len(query.Data))
		resp, err := l.client.Queries(query)
		if err != nil {
			l.logger.Warn("Sending local queries failed.", "err", err)
			continue
		}
		if resp.Accepted*9 <= resp.Received {
			l.logger.Warn("Queries bad acceptance rate detected.", "received", resp.Received, "accepted", resp.Accepted)
		}
		l.logger.Info("Local queries were successfully send.", "received", resp.Received, "accepted", resp.Accepted)

		if err = os.Remove(file); err != nil {
			l.logger.Warn("Removing queries failed.", "file", file, "err", err)
		}
	}

}

func (l *listenHandler) SniffLoop() {
	for {
		select {
		case <-l.quit:
			l.sniffer.Close()
			return
		default:
			entries := l.sniffer.PacketToEntry(l.sniffer.Sniff())
			if len(entries) == 0 {
				continue
			}
			l.logger.Debug("Sniffed:", "FQDN", entries[0].FQDN, "IP", entries[0].IP.String())
			l.queries <- entries
		}
	}
}
