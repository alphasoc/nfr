# Namescore
AlphaSOC **Namescore** is a lightweight Linux client used to capture DNS query events from a network and submit them to _api.alphasoc.net_ for processing. The AlphaSOC DNS Analytics Engine quickly identifies security threats within DNS material (e.g. C2 traffic, DNS tunneling, ransomware, and policy violations such as cryptocurrency mining and third-party VPN use).

## Prerequisites
Namescore requires `libpcap-dev` and uses `govendor` for vendoring. Installation steps are as follows.

### Under Debian and Ubuntu
```
# apt-get install libpcap-dev
# go get -u github.com/kardianos/govendor
```

### Under Red Hat, Fedora, and CentOS
```
< instructions >
```


## Installation
Follow these steps to install Namescore:
```
# git clone https://github.com/alphasoc/namescore.git
# cd namescore
# govendor sync
# go install
```

Upon installation, test Namescore as follows:
```
# namescore
namescore is application which captures DNS requests and provides
deep analysis and alerting of suspicious events,
identifying gaps in your security controls and highlighting targeted attacks.

Usage:
  namescore [command]

  Available Commands:
    listen      daemon mode
    register    Acquire and register API key.
    status      Shows status of namescore

    Use "namescore [command] --help" for more information about a command.
```

## Configuration

Namescore expects to find its configuration file in `/etc/alphasoc/namescore.toml`. You can find an example configuration file in the repository's root directory. Copy this file to `/etc/alphasoc` and if you already have AlphaSOC API key, update the file with your key. Otherwise, simply run `namescore` which will prompt you for configuration and account details, e.g.

```
# namescore
AlphaSOC Namescore Setup and API Key Generation

Select a network interface to monitor for DNS traffic
Detected interfaces:
  - lo
  - eth0

Interface to monitor: eth0

Provide your details to generate an API key and complete setup. A valid email
address is required to activate the key. By performing this request you agree to
our Terms of Service and Privacy Policy (https://www.alphasoc.com/terms-of-service)

Full name: Joey Bag O'Donuts
Organization: AlphaSOC
Email: joey@alphasoc.com

Success! Check your email and click the verification link to activate your API key
```

## Monitoring Scope
Use directives within `/etc/namescore/whitelist.toml` to define the monitoring scope. DNS requests from the IP ranges within scope will be captured and sent to the AlphaSOC DNS Analytics API for scoring, and domains that are whitelisted (e.g. internal trusted domains) will be ignored and not sent to the API. CIDR notation is supported, and entire domains can be whitelisted using `*`, as follows:

```
[networks]
1.1.1.250
10.100.1.5/32
192.168.1.0/24
127.0.0.1/8

[domains] 
*.example.com 
whatever.com
google.com
site.net
internal.company.org
```

## Status command
Use `namescore status` to quickly check the most important parameters and diagnose basic problems.

## Running
Run `namescore listen` in tmux or screen, or provide a startup script to start namescore at system startup. To debug possible problems, you can use `namescore listen debug` which is more verbose.
