package config

const (
	// File where follow ID after each response is stored
	FollowFilePath = "/home/phob0s/alphasoc/follow"

	// File where alerts are stored
	// Format of alerts is:
	// timestamp;ip;record_type;domain;severity;threat_definition;flags
	AlertFilePath = "/home/phob0s/alphasoc/namescore.log"

	// File where are stored informations about:
	// - API key
	// - Network interface which should namescore bind to
	ConfigFilePath = "/home/phob0s/alphasoc/namescore.toml"

	// AlphaSOC server address
	AlphaSocAddress = "http://127.0.0.1:8080"

	// Time interval in seconds which determines how often queries are sent
	// to AlphaSOC cloud
	SendIntervalTime = 60

	// Amount interval which determines how many DNS requests are needed
	// to be collected to send data to AlphaSOC
	// It has higher priority than time interval parameter.
	SendIntervalAmount = 1000

	// Time interval determining how often alerts are collected from
	// AlphaSOC cloud
	AlertRequestInterval = 300
)
