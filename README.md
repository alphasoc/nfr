# Network Flight Recorder
**NFR** is a lightweight application which processes network traffic using the [AlphaSOC Analytics Engine.](https://alphasoc.com) NFR can monitor log files on disk (e.g. Microsoft DNS debug logs, Bro IDS logs) or run as a network sniffer under Linux to score traffic. Upon processing the data, alerts are presented in either JSON or CEF format for escalation via syslog.

## Installation
[Download NFR from the releases section.](https://github.com/alphasoc/nfr/releases) Once downloaded, run NFR as follows:

```
# nfr --help
Network Flight Recorder (NFR) is an application which captures network traffic
and provides deep analysis and alerting of suspicious events, identifying gaps
in your security controls, highlighting targeted attacks, and policy violations.

Usage:
  nfr [command] [argument]

Available Commands:
  account register       Generate an API key via the licensing server
  account reset [email]  Reset the API key associated with a given email address
  account status         Show the status of your AlphaSOC API key and license
  read [file]            Read network events from a PCAP file on disk
  start                  Start processing network events (inputs defined in config)
  version                Show the NFR binary version
  help                   Provides help and usage instructions

Use "nfr [command] --help" for more information about a given command.
```

## Configuration
NFR expects to find its configuration file in `/etc/nfr/config.yml`. If you installed the Debian package, an example `config.yml` would have been installed for you in `/etc/nfr`. Otherwise, you can find the example [`config.yml`](https://github.com/alphasoc/nfr/blob/master/config.yml) file in the repository's root directory. The file defines the AlphaSOC Analytics Engine location and configuration, input preferences (e.g. log files to monitor), output preferences, and other variables. If you already have AlphaSOC API key, update the file with your key and place within the `/etc/nfr/` directory.

If you are a new user, simply run `nfr account register` (as root) to create the file and generate an API key, e.g.

```
# nfr account register
Please provide your details to generate an AlphaSOC API key.
A valid email address is required for activation purposes.

By performing this request you agree to our Terms of Service and Privacy Policy
(https://www.alphasoc.com/terms-of-service)

Full Name: Joey Bag O'Donuts
Email: joey@example.org

Success! The configuration has been written to /etc/nfr/config.yml
Next, check your email and click the verification link to activate your API key.
```

## Processing events from the network
If you are running NFR under Linux, use the `sniffer` directive within `/etc/nfr/config.yml` to specify a network interface to monitor. To monitor interface `eth1` you can use the configuration below.

```
  sniffer:
    enabled: true
    interface: eth1
```

## Processing events from disk
Use the `monitor` directive within `/etc/nfr/config.yml` to actively read log files from disk. Bro IDS (Zeek) logs both DNS, IP, and HTTP traffic, whereas Suricata only logs DNS traffic. To monitor both Bro `conn.log`, `dns.log`, and `http.log` output you can use this configuration:

```
monitor:
  - format: bro
    type: dns
    file: /path/to/dns.log
  - format: bro
    type: ip
    file: /path/to/conn.log
  - format: bro
    type: http
    file: /path/to/http.log
```

To process Suricata DNS output you would use:

```
monitor:
  - format: suricata
    type: dns
    file: /path/to/eve.json
```

Microsoft DNS (`format: msdns`) and BIND over syslog (`format: syslog-named`) are also supported at this time. Please contact support@alphasoc.com if you have a particular use case and wish to monitor a file format that is not listed here. If you wish to process events from a given PCAP file on disk, please use the `read` command when running NFR.

## Processing events from Elasticsearch
Use the `elastic` directive within `/etc/nfr/config.yml` to retrieve telemetry from Elasticsearch. Both Elastic Cloud and local deployments are supported. For configuration details, see comments in `config.yml`

If your data is ECS-compliant, configuration is straightforward:
```yaml
  elastic:
    enabled: true
    hosts:
      - localhost:9200
    # If authorization is needed:
    # api_key: ... # or:
    # username: admin
    # password: password

    searches:
      - event_type: dns
        indices:
          - filebeat-*
        index_schema: ecs
      - event_type: ip
        indices:
          - filebeat-*
        index_schema: ecs
      - event_type: http
        indices:
          - filebeat-*
        index_schema: ecs
```

Currently ECS, Graylog and custom schemas are supported. For custom schemas you can define your own search terms and/or list fields that must be present in a document to be picked by nfr for processing.

Under the hood, nfr periodically runs a search:
```json
{
  "docvalue_fields": [
    {
      "field": "@timestamp", // field name defined in config
      "format": "strict_date_time"
    },
    {
      "field": "event.ingested", // field name defined in config
      "format": "strict_date_time"
    }
  ],
  "_source": [
    // configurable field names
    "source.ip",
    "source.port",
    "dns.question.name",
    "dns.question.type"
  ],
  "size": 100,
  "query": {
    "bool": {
      "must": [
        // configurable field names
        {"exists": {"field": "source.ip"}},
        {"exists": {"field": "dns.question.name"}},
        {"exists": {"field": "dns.question.type"}}
      ],
      "filter": [
        {
          // configurable filter term
          "term": {"tags": "zeek.dns"}
        },
        {
          "range": {
            // automatically inserted to handle pagination
            "event.ingested": {
              "gte": "2021-03-05T13:28:49.254Z"
            }
          }
        }
      ]
    }
  },
  "sort": [
    {
      "event.ingested": "asc"
    }
  ],
  "pit": {
    "id": "w62xAwU..." // Every search runs inside Point-In-Time
  },
  "search_after": [
    1614950929254,
    "S8eTAngB14iTwI_2kzVm"
  ]
}
```

## Monitoring scope
Use directives within `/etc/nfr/scope.yml` to define the monitoring scope. If you installed the Debian package, an example `scope.yml` would have been installed for you in `/etc/nfr`. Otherwise, you can find the example [`scope.yml`](https://github.com/alphasoc/nfr/blob/master/scope.yml) file in the repository's root directory. Network traffic from the IP ranges within scope will be processed by the AlphaSOC Analytics Engine, and domains that are whitelisted (e.g. internal trusted domains) will be ignored. Adjust `scope.yml` to define the networks and systems that you wish to monitor, and the events to discard, e.g.

```
groups:
  private_network:
    label: "Private network"
    in_scope:
      - 10.0.0.0/8
      - 192.168.0.0/16
    out_scope:
      - 10.1.0.0/16
      - 10.2.0.254/32
    trusted_domains:
      - "*.example.com"
      - "*.alphasoc.net"
      - "google.com"
  public_network:
    label: "Private network"
    in_scope:
      - 131.1.0.0/16
  my_own_group:
    label: "Custom group"
    in_scope:
      - 131.2.0.0/16
    trusted_domains:
      - "site.net"
      - "*.internal.company.org"
```

## Running NFR
You may run `nfr start` via `tmux` or `screen` under Linux, or set up a service (detailed in the following section). NFR returns alert data in JSON format to `stderr`. Below an example in which raw the JSON is both stored on disk at `/tmp/alerts.json` and rendered via `jq` to make it human-readable in the terminal.

```
# nfr start 2>&1 >/dev/null | tee /tmp/alerts.json | jq .
{
  "type": "alert",
  "eventType": "dns",
  "flags": [
    "apt",
    "freedns"
  ],
  "groups": [
    {
      "label": "default",
      "desc": "Default"
    }
  ],
  "threats": {
    "c2_communication": {
      "severity": 5,
      "desc": "C2 communication attempt indicating infection",
      "policy": false
    }
  },
  "ts": "2018-09-03T09:39:47Z",
  "srcIp": "10.15.0.4",
  "query": "microsoft775.com",
  "recordType": "A"
}
```

## Running NFR as a service

### Under Linux
If you are using a current Linux distribution (e.g. RHEL7, Ubuntu 16), it will have [systemd](https://www.freedesktop.org/wiki/Software/systemd/) installed. Follow these steps as root to run NFR as a service. *NOTE*: If you installed the Debian package, you can skip steps 1-3 below.

1. Create the NFR configuration directory and copy `config.yml` and `scope.yml` into it

```
mkdir /etc/nfr
cp config.yml /etc/nfr
cp scope.yml /etc/nfr
```

2. Copy the `nfr` binary into `/usr/local/bin` and ensure it's executable

```
cp nfr /usr/local/bin
chmod a+x /usr/local/bin/nfr
```
3. Copy the sample NFR service file [`nfr.service`](https://github.com/alphasoc/nfr/blob/master/nfr.service) to `/etc/systemd/system/`

4. Use `systemctl` to enable NFR, start the service, and review its status

```
systemctl enable nfr
systemctl start nfr
systemctl status nfr
```

Once NFR is installed, you can view logs and troubleshoot using `journalctl -u nfr`.

To stop and remove the service, follow these steps:

```
systemctl stop nfr
systemctl disable nfr
rm /etc/systemd/system/nfr.service
```

### Under Microsoft Windows
To run NFR as a service under Windows, first install [NSSM](http://nssm.cc), and follow the steps below within PowerShell as Administrator.

1. Create the NFR configuration directory and copy `config.yml` and `scope.yml` into it

```
New-Item -ItemType directory -Path $Env:AppData\nfr
Move-Item -Path config.yml -Destination $Env:AppData\nfr
Move-Item -Path scope.yml -Destination $Env:AppData\nfr
```

2. Use NSSM to install the service, start it, and review status (__note:__ modify the path to `nfr.exe` as needed)

```
nssm.exe install nfr C:\path\to\nfr.exe start
nssm.exe start nfr
nssm.exe status nfr
```

To stop and remove the service, follow these steps:

```
nssm.exe stop nfr
nssm.exe remove nfr
```
