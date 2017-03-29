# Namescore
**Namescore** is a lightweight client which uses AlphaSOC DNS Analytics API to identify malware and suspicious behavior within your networks.

## Installation
Currently only Linux is supported. To compile `libpcap-dev` is needed. Namescore uses govendor for vendoring.

1. Install libpcap-dev, on debian/ubuntu machines:
```
# apt-get install libpcap-dev
```

2. Install govendor
```
# go get -u github.com/kardianos/govendor
```

3. Install namescore
```
# git clone https://github.com/alphasoc/namescore.git
# cd namescore
# govendor sync
# go install
```

4. Test installation
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

Namescore expects to find its configuration file in `/etc/alphasoc/namescore.toml`. You can find an example configuration file in the repository's root directory. Copy this file to `/etc/alphasoc` and if you already have AlphaSOC API Key, update the file with your key. Otherwise, you can use `namescore register` command which will create a new configuration file if it doesn't exist, configure your network interface and request a trial API key from AlphaSOC.

### Whitelist file
You can whitelist specific networks or domains from being processed by AlphaSOC by including them in `/etc/namescore/whitelist.toml`. For example:

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
You can use `namescore status` to quickly check the most important parameters and diagnose basic problems.

## Running
Run `namescore listen` in tmux or screen, or provide a startup script to start namescore at system startup. To debug possible problems, you can use `namescore listen debug` which is more verbose.
