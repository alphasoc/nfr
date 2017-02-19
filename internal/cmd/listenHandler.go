package cmd

import (
	"fmt"
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
	sniffer    dns.DNSCapture
	cfg        *config.Config
	quit       chan bool
	queries    chan []asoc.Entry
}

func (l *listenHandler) getAlerts() {

	timer := make(chan bool)
	go func() {
		time.Sleep(time.Second * l.cfg.GetAlertRequestInterval())
		timer <- true
	}()

	follow := asoc.ReadFollow(l.cfg.GetFollowFilePath())

	for {
		select {
		case <-timer:
			status, err := l.client.AccountStatus()
			if err != nil {
				l.logger.Warn("Failed to check account status", "err", err)
				continue
			}
			if status.Expired || !status.Registered {
				l.logger.Warn("Account status is expired or not registered")
				for _, msg := range status.Messages {
					l.logger.Warn("Server response:", "msg", msg.Body)
				}
				continue
			}

			if events, err := l.client.Events(follow); err == nil {
				if err := asoc.StoreAlerts(l.cfg.GetAlertFilePath(), events.Strings()); err != nil {
					l.logger.Warn("Failed to store alerts", "error", err)
					continue
				}
				follow = events.Follow
			} else {
				l.logger.Warn("Failed to retrieve events", "err", err)
			}

		case <-l.quit:
			l.logger.Info("Closed getAlerts")
			return
		}
	}
}

func (l *listenHandler) sendQueries() {
	for {
		senddata := <-l.queries

		go func() {
			if len(senddata) == 0 {
				return
			}
			request := &asoc.QueriesReq{Data: senddata}
			fmt.Println("sendQueries() sending")
			resp, err := l.client.Queries(request)
			if err != nil {
				if err != l.queryStore.Store(request) {
					l.logger.Warn("Storing queries failed.", "err", err)
				}
				return
			}
			if rate := resp.Received * 100 / resp.Accepted; rate < 90 {
				l.logger.Warn("Queries bad acceptance rate detected.", "received", resp.Received, "accepted", resp.Accepted)
			}
		}()
	}
}

func (l *listenHandler) sendLocalQueries() {
	for {
		time.Sleep(60 * time.Second)
		files := l.queryStore.GetQueryFiles()

		for _, file := range files {
			query, err := l.queryStore.Read(file)
			if err != nil {
				l.logger.Warn("Reading queries failed.", "err", err)
				os.Remove(file)
				continue
			}
			resp, err := l.client.Queries(query)
			if err != nil {
				continue
			}
			if rate := resp.Received * 100 / resp.Accepted; rate < 90 {
				l.logger.Warn("Queries bad acceptance rate detected.", "received", resp.Received, "accepted", resp.Accepted)
			}
			os.Remove(file)
		}
	}

}

func (l *listenHandler) sniff() {
	l.queries = make(chan []asoc.Entry, 10)
	var buffer []asoc.Entry

	for {
		packet := l.sniffer.Sniff()
		if entries := l.sniffer.PacketToEntry(packet); entries != nil {
			buffer = append(buffer, entries...)
			if len(buffer) > l.cfg.GetSendIntervalAmount() {
				l.queries <- buffer
				buffer = nil
			}
		}

	}
}
