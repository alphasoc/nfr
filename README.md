# Namescore
**Namescore** is a lightweight Linux client used to submit DNS events to _api.alphasoc.net_ for processing and retrieve alerts. The AlphaSOC DNS Analytics Engine quickly identifies security threats within DNS material (e.g. C2 traffic, DNS tunneling, ransomware, and policy violations such as cryptocurrency mining and third-party VPN use). Namescore can be run as a sniffer, or can read PCAP data from disk.

Alert data is returned in JSON format upon processing, describing the threats and policy violations.

## Prerequisites
Namescore requires the development library for `libpcap`. Installation steps are as follows (as _root_).

### Under Debian and Ubuntu
```
# apt-get install libpcap-dev
```

### Under RHEL7
```
# yum-config-manager --enable rhel-7-server-optional-rpms
# yum install libpcap-devel
# yum-config-manager --disable rhel-7-server-optional-rpms
```

## Namescore installation
Use the following command to install Namescore:
```
# go get github.com/alphasoc/namescore
```

Upon installation, test Namescore as follows:
```
# namescore --help
Namescore is an application which captures DNS requests and provides deep analysis
and alerting of suspicious events, identifying gaps in your security controls and
highlighting targeted attacks and policy violations.

Usage:
  namescore [command] [argument]

Available Commands:
  account register       Generate an API key via the licensing server
  account reset [email]  Reset the API key associated with a given email address
  account status         Show the status of your AlphaSOC API key and license
  listen                 Start the sniffer and score live DNS events
  read [file]            Process DNS events stored on disk in PCAP format
  version                Show the Namescore binary version
  help                   Provides help and usage instructions

Use "namescore [command] --help" for more information about a given command.
```

## Configuration
Namescore expects to find its configuration file in `/etc/namescore/config.yml`. You can find an example [`config.yml`](https://github.com/alphasoc/namescore/blob/master/config.yml) file in the repository's root directory. The file defines the network interface to monitor for DNS traffic, output preferences, and other variables. If you already have AlphaSOC API key, update the file with your key and place within the `/etc/namescore/` directory.

If you are a new user, simply run `namescore account register` to create the file and generate an API key, e.g.

```
# namescore account register
Please provide your details to generate an AlphaSOC API key.
A valid email address is required for activation purposes.

By performing this request you agree to our Terms of Service and Privacy Policy
(https://www.alphasoc.com/terms-of-service)

Full Name: Joey Bag O'Donuts
Email: joey@example.org

Success! The configuration has been written to /etc/namescore/config.yml
Next, check your email and click the verification link to activate your API key.
```

## Monitoring scope
Use directives within `/etc/namescore/scope.yml` to define the monitoring scope. You can find an example [`scope.yml`](https://github.com/alphasoc/namescore/blob/master/scope.yml) file in the repository's root directory. DNS requests from the IP ranges within scope will be processed by the AlphaSOC DNS Analytics API, and domains that are whitelisted (e.g. internal trusted domains) will be ignored. Adjust `scope.yml` to define the networks and systems that you wish to monitor, and the events to discard, e.g.

```
groups:
  private_network:
    networks:
      - 10.0.0.0/8
      - 192.168.0.0/16
    exclude:
      networks:
        - 10.1.0.0/16
        - 10.2.0.254
      domains:
        - "*.example.com"
        - "*.alphasoc.net"
        - "google.com"
  public_network:
    networks:
    - 131.1.0.0/16
  my_own_group:
    networks:
    - 131.2.0.0/16
    exclude:
      domains:
        - "site.net"
        - "*.internal.company.org"
```

## Running Namescore
You may run `namescore listen` in tmux or screen, or provide a startup script to run on boot. Namescore returns alert data in JSON format to `stderr`. Below an example in which raw the JSON is both stored on disk at `/tmp/alerts.json` and rendered via `jq` to make it human-readable in the terminal.

```
# namescore listen 2>&1 >/dev/null | tee /tmp/alerts.json | jq .
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
