# Network Behavior Analytics for Graylog

This content pack establishes a GELF input by which AlphaSOC alerts can be sent to Graylog by [Network Flight Recorder (NFR)](https://github.com/alphasoc/nfr), and a dashboard to summarize infected hosts and anomalies within the environment. NFR performs scoring of network traffic (DNS and IP events) which can be collected on the wire, or loaded via Bro IDS, Suricata, or other sources.

## Provided Content

* A GELF input on TCP port 12201 to receive alerts from NFR
* A dashboard which summarizes the alerts and suspicious domains

## AlphaSOC Alert Format

The alert format and fields within Graylog are described in the table below.

| Field            | Description                                                              |
|------------------|--------------------------------------------------------------------------|
| `host`           | NFR engine generating the alert                                          |
| `engine_agent`   | NFR engine version                                                       |
| `original_event` | Timestamp of the original network event (e.g. DNS request)               |
| `src_ip`         | IP address of the client / endpoint generating the traffic               |
| `dest_ip`        | IP address of a suspicious destination                                   |
| `threat`         | Short threat label (e.g. c2_communication)                               |
| `message`        | Long threat label (e.g. "C2 communication attempt indicating infection") |
| `severity`       | Event severity (5: critical, 4: high, 3: medium, 2: low, 1: info)        |
| `query`          | DNS request FQDN associated with the alert (e.g. badguy123.ru)           |
| `record_type`    | DNS request record type associated with the alert (e.g. A, MX, SRV)      |

## Screenshot

![AlphaSOC dashboard](https://github.com/alphasoc/nfr/blob/master/graylog/dashboard.png)
