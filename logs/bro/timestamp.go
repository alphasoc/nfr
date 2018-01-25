package bro

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func parseEpochTime(t string) (time.Time, error) {
	s := strings.Split(t, ".")
	if len(s) != 2 {
		return time.Time{}, fmt.Errorf("invalid timestamp %s", t)
	}

	sec, err := strconv.ParseInt(s[0], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %s", t)
	}

	nsec, err := strconv.ParseInt(s[1], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %s", t)
	}

	return time.Unix(sec, nsec), nil
}
