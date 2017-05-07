package runner

import (
	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/queries"
	"github.com/alphasoc/namescore/sniffer"
	"github.com/alphasoc/namescore/utils"
)

func Start(c *client.Client, cfg *config.Config) error {
	s, err := sniffer.NewDNSSnifferFromInterface(cfg.Network.Interface, cfg.Network.Protocols, cfg.Network.Port)
	if err != nil {
		return err
	}

	buf := queries.NewBuffer(queries.Size(cfg.Queries.Size), queries.FailedFile(cfg.Queries.Failed.File))
	if err := loop(c, cfg, buf); err != nil {
		return err
	}
	return nil
}

func Send(c *client.Client, cfg *config.Config, files []string) error {
	for _, file := range files {
		s, err := sniffer.NewDNSSnifferFromFile(file, cfg.Network.Protocols, cfg.Network.Port)
		if err != nil {
			return err
		}

		buf := queries.NewBuffer(queries.Size(cfg.Queries.Size))
		if err := loop(c, cfg, buf); err != nil {
			return err
		}
		if err := os.Rename(file, file+"."+time.Now().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	return nil
}

func loop(c *client.Client, cfg *config.Config, buf *queries.Buffer) error {
	df := filter.NewGroupFilter(cfg)
	for packet := range s.Packets() {
		buf.Write(packet)
		if buf.Len() < cfg.Queries.Size {
			continue
		}
		if _, err := c.Queries(utils.DecodePackets(df.Filter(buf.Read()))); err != nil {
			return err
		}
		buf.Clear()
	}

	if _, err := c.Queries(utils.DecodePackets(df.Filter(ds.Filter(buf.Read())))); err != nil {
		return err
	}
}
