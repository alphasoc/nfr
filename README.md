# Network Flight Recorder
**NFR** is a lightweight application which captures network traffic and provides alerting of suspicious events (e.g. C2 beacons, DGA traffic, ransomware, DNS tunneling, and cryptomining). The utility collects events via a network interface or processing of log files (e.g. Bro IDS or Suricata logs), scores them via the AlphaSOC Analytics Engine, and outputs alerts for escalation.

Alert data is returned in JSON format upon processing, describing the threats and policy violations.

## Prerequisites
NFR requires the `libpcap` development library. Installation steps are as follows.

### Under Debian and Ubuntu
```
# sudo apt-get install libpcap-dev
```

### Under RHEL7
```
# sudo yum-config-manager --enable rhel-7-server-optional-rpms
# sudo yum install libpcap-devel
# sudo yum-config-manager --disable rhel-7-server-optional-rpms
```

## NFR installation
Use the following command to install NFR:
```
# go get -u github.com/alphasoc/nfr/...
```

Upon installation, test NFR as follows:
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
NFR expects to find its configuration file in `/etc/nfr/config.yml`. You can find an example [`config.yml`](https://github.com/alphasoc/nfr/blob/master/config.yml) file in the repository's root directory. The file defines the AlphaSOC Analytics Engine location and configuration, input preferences (e.g. log files to monitor), output preferences, and other variables. If you already have AlphaSOC API key, update the file with your key and place within the `/etc/nfr/` directory.

If you are a new user, simply run `nfr account register` to create the file and generate an API key, e.g.

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

## Processing events from Bro and Suricata
Use the `monitor` directive within `/etc/nfr/config.yml` to actively read log files from disk. Bro IDS logs both DNS and IP traffic, whereas Suricata only logs DNS traffic. To monitor both Bro `conn.log` and `dns.log` output you can use this configuration:

```
monitor:
  - format: bro
    type: dns
    file: /path/to/dns.log
  - format: bro
    type: ip
    file: /path/to/conn.log
```

To process Suricata DNS output you would use:

```
monitor:
  - format: suricata
    type: dns
    file: /path/to/eve.json
```

Microsoft DNS (`format: msdns`) is also supported, and support for other log types is coming. Please contact support@alphasoc.com if you have a particular use case and wish to monitor a file format that is not listed here. If you wish to process events from a PCAP file on disk, please use the `read` command when running NFR.

## Monitoring scope
Use directives within `/etc/nfr/scope.yml` to define the monitoring scope. You can find an example [`scope.yml`](https://github.com/alphasoc/nfr/blob/master/scope.yml) file in the repository's root directory. Network traffic from the IP ranges within scope will be processed by the AlphaSOC Analytics Engine, and domains that are whitelisted (e.g. internal trusted domains) will be ignored. Adjust `scope.yml` to define the networks and systems that you wish to monitor, and the events to discard, e.g.

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
You may run `nfr start` in tmux or screen, or provide a startup script to run on boot. NFR returns alert data in JSON format to `stderr`. Below an example in which raw the JSON is both stored on disk at `/tmp/alerts.json` and rendered via `jq` to make it human-readable in the terminal.

```
# nfr start 2>&1 >/dev/null | tee /tmp/alerts.json | jq .
{
  "follow": "4.9b3db",
  "more": false,
  "events": [
    {
      "type": "alert",
      "ts": [
        "2017-05-22T16:16:56+02:00"
      ],
      "ip": "10.0.2.15",
      "record_type": "A",
      "fqdn": "microsoft775.com",
      "risk": 5,
      "flags": [
        "c2"
      ],
      "threats": [
        "c2_communication"
      ]
    }
  ],
  "threats": {
    "c2_communication": {
      "title": "C2 communication attempt indicating infection",
      "severity": 5,
      "policy": false,
      "deprecated": false
    }
  }
}
```
