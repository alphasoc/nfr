package runner

import (
	"os"
	"time"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/filter"
	"github.com/alphasoc/namescore/sniffer"
	"github.com/alphasoc/namescore/utils"
)

func Start(cfg *config.Config, c *client.Client) error {
	s, err := sniffer.NewDNSSnifferFromInterface(cfg.Network.Interface, cfg.Network.Protocols, cfg.Network.Port)
	if err != nil {
		return err
	}

	buf, err := queries.NewBuffer(queries.Size(cfg.Queries.BufferSize), queries.FailedFile(cfg.Queries.Failed.File))
	if err != nil {
		return err
	}

	if err := loop(cfg, c, s, buf); err != nil {
		return err
	}
	return nil
}

func Send(cfg *config.Config, c *client.Client, file string) error {
	s, err := sniffer.NewDNSSnifferFromFile(file, cfg.Network.Protocols, cfg.Network.Port)
	if err != nil {
		return err
	}

	// ignore error, because the failed filed is not being opened
	buf, _ := utils.NewPacketBuffer(utils.Size(cfg.Queries.BufferSize))
	if err := loop(cfg, c, s, buf); err != nil {
		return err
	}
	if err := os.Rename(file, file+"."+time.Now().Format(time.RFC3339)); err != nil {
		return err
	}
	return nil
}

func loop(cfg *config.Config, c *client.Client, s *sniffer.Sniffer, buf *queries.Buffer) error {
	df := filter.NewGroupsFilter(cfg)
	for packet := range s.Packets() {
		buf.Write(packet)
		if buf.Len() < cfg.Queries.BufferSize {
			continue
		}
		if _, err := c.Queries(utils.DecodePackets(df.Filter(buf.Read()))); err != nil {
			return err
		}
		buf.Clear()
	}

	if _, err := c.Queries(utils.DecodePackets(df.Filter(buf.Read()))); err != nil {
		return err
	}
	return nil
}
