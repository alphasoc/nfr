package asoc

import (
	"bufio"
	"namescore/utils"
	"os"
)

type AlertStore struct {
	file *os.File
	buf  *bufio.Writer
}

func OpenAlerts(file string) (a *AlertStore, err error) {
	if utils.FileExists(file) == false {
		if err = utils.CreateDirForFile(file); err != nil {
			return nil, err
		}
	}

	a = &AlertStore{}

	if a.file, err = os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err != nil {
		return nil, err
	}

	a.buf = bufio.NewWriter(a.file)

	return a, nil
}

func (a *AlertStore) Close() error {
	if a.file != nil {
		a.buf.Flush()
		return a.file.Close()
	}
	return nil
}

func (a *AlertStore) Write(alerts []string) {
	for _, l := range alerts {
		a.buf.WriteString(l)
		a.buf.WriteByte('\n')
	}
}

func (a *AlertStore) Flush() {
	a.buf.Flush()
}
