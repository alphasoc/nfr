package config

import "time"

const (
	// File where follow ID after each response is stored
	followFilePath = "/home/phob0s/alphasoc/follow"

	// File where alerts are stored
	// Format of alerts is:
	// timestamp;ip;record_type;domain;severity;threat_definition;flags
	alertFilePath = "/home/phob0s/alphasoc/namescore.log"

	// File where are stored informations about:
	// - API key
	// - Network interface which should namescore bind to
	configFilePath = "/home/phob0s/alphasoc/namescore.toml"

	// Directory where are stored queries which sending failed.
	failedQueriesDir = "/home/phob0s/alphasoc/backup"

	// WhitelistFilePath stores information about:
	// - which subnetworks should not be taken into account
	// - which domains should not been taken into account
	whitelistFilePath = "/home/phob0s/alphasoc/whitelist.toml"

	// AlphaSOC server address
	alphaSOCAddress = "http://127.0.0.1:8080"

	// Time interval in seconds which determines how often queries are sent
	// to AlphaSOC cloud
	sendIntervalTime = 10 * time.Second

	// Amount interval which determines how many DNS requests are needed
	// to be collected to send data to AlphaSOC
	// It has higher priority than time interval parameter.
	sendIntervalAmount = 100

	// Time interval determining how often alerts are collected from
	// AlphaSOC cloud
	alertRequestInterval = 20 * time.Second

	// Number of chunks of failed queries which are stored locally
	// Total amout of possible stored queries on disk can be calculated with:
	//  failedQueriesCountLimit * querySendAmount
	failedQueriesLimit = 100

	// Time interval determining how often failedQueriesDir is scanned for
	// queries saved in file.
	localQueriesInterval = 20 * time.Second
)
