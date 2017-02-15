package cmd

import (
	"time"

	"github.com/alphasoc/namescore/internal/asoc"
	"github.com/alphasoc/namescore/internal/config"
	log "github.com/inconshreveable/log15"
)

type listenHandler struct {
	logger  log.Logger
	client  asoc.AlphaSOCAPI
	cfg     *config.Config
	quit    chan bool
	queries chan []asoc.Entry
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
			} else if status.Expired == true {
				l.logger.Warn("Account status is expired")
				continue
			} else if status.Registered == false {
				l.logger.Warn("Account status is not registered.")
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
	senddata := <-l.queries

	go func() {

		if len(senddata) == 0 {
			return
		}

		resp, err := l.client.Queries(&asoc.QueriesReq{Data: senddata})
		if err != nil {
			//errorhandling
		}
		if rate := resp.Received * 100 / resp.Accepted; rate < 90 {
			l.logger.Warn("Queries bad acceptance rate detected.", "received", resp.Received, "accepted", resp.Accepted)
		}
	}()
}

func (l *listenHandler) sendLocalQueries() {

}
