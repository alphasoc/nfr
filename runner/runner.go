package runner

import (
	"io"
	"log"
	"os"

	"github.com/alphasoc/namescore/client"
	"github.com/alphasoc/namescore/config"
	"github.com/alphasoc/namescore/queries"
	"github.com/google/gopacket"
)

func Start(cfg *config.Config, c *client.Client) error {
	if cfg.Queries.Failed.File != "" {
		// try to send old data, on success remove the file
		if err := Send(c, []string{cfg.Queries.Failed.File}); err != nil {
			return err
		}
		os.Remove(cfg.Queries.Failed.File)
	}

	ms, err := queries.NewMemStorage(cfg.Queries.BufferSize)
	if err != nil {
		return err
	}

	fs, err := queries.NewFileStorage(cfg.Queries.Failed.File)
	if err != nil {
		return err
	}

	packetC := make(chan gopacket.Packet, cfg.Queries.BufferSize)
	sniffer.Snif(packetC)
	go func() {
		for packet := range packetC {
			ms.Write([]gopacket.Packet{packet})
			if ms.Len() < cfg.Queries.BufferSize {
				continue
			}

			packets, _ := ms.ReadAll()

			req := utils.DecodePackets(packets)
			resp, err := c.Queries(req)
			if err == nil {
				continue
			}

			log.Println("failed to send ", err)
			if fs == nil {
				continue
			}

			_, err := fs.Write(packets)
			if err != nil {
				log.Println("failed to send ", err)
			}
		}
	}()

	// Flush
	go func() {
		tC := timer.New(cfg.Queries.FlushInterval)
		for range tC {
			packets, _ := ms.ReadAll()
			req := utils.DecodePackets(packets)
			resp, err := c.Queries(req)
			if err == nil {
				continue
			}
			log.Println("failed to send ", err)
			if fs == nil {
				continue
			}

			_, err := fs.Write(packets)
			if err != nil {
				log.Println("failed to send ", err)
			}
		}
	}()

	return nil
}

func Send(c *client.Client, files []string) error {
	for i := range files {
		fs, err := queries.NewFileStorage(files[i])
		if err != nil {
			return err
		}

		for packets, err := fs.Read(); err != io.EOF; packets, err = fs.Read() {
			if err != nil && err != io.EOF {
				return err
			}

			req := utils.DecodePackets(packets)
			resp, err := c.Queries(req)
			if err != nil {
				return err
			}

			log.Println(resp.Received, resp.Accepted, resp.Rejected)
		}
	}
	return nil
}
