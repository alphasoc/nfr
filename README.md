# Namescore
AlphaSOC **Namescore** is a lightweight Linux client used to capture DNS query events from a network and submit them to _api.alphasoc.net_ for processing. The AlphaSOC DNS Analytics Engine quickly identifies security threats within DNS material (e.g. C2 traffic, DNS tunneling, ransomware, and policy violations such as cryptocurrency mining and third-party VPN use).

## Prerequisites
Namescore requires the development library for libpcap. Installation steps are as follows (as root).

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

## Installation
Follow these steps to install Namescore:
```
# go get github.com/alphasoc/namescore.git
```

Upon installation, test Namescore as follows:
```
# namescore --help
namescore is application which captures DNS requests and provides
deep analysis and alerting of suspicious events,
identifying gaps in your security controls and highlighting targeted attacks.

Usage:
  namescore listen|register|status [flags]
  namescore [command]

Available Commands:
  account     Manage AlphaSOC account
  help        Help about any command
  send        Send dns queries stored in pcap file
  start       Start namescore dns sniffer
  version     Print the version number of namescore

Use "namescore [command] --help" for more information about a command.
```

## Configuration

Namescore expects to find its configuration file in `/etc/namescore.yml`. You can find an example configuration file namescore.yml in the repository's root directory. Copy this file to `/etc/` and if you already have AlphaSOC API key, update the file with your key. Otherwise, simply run `namescore` which will prompt you for configuration and account details, e.g.

```
# namescore
Provide your details to generate an API key and complete setup.
A valid email address is required to activate the key. 

By performing this request you agree to our Terms of Service and Privacy Policy
https://www.alphasoc.com/terms-of-service

Full Name: Joey Bag O'Donuts
Email: joey@alphasoc.com

Success! Check your email and click the verification link to activate your API key.
```

## Monitoring Scope
Use directives within `/etc/namescore/whitelist.yml` to define the monitoring scope. DNS requests from the IP ranges within scope will be captured and sent to the AlphaSOC DNS Analytics API for scoring, and domains that are whitelisted (e.g. internal trusted domains) will be ignored and not sent to the API, e.g.

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

## Account status command
Use `namescore account status` to quickly check the most important parameters about account.

## Running
Run `namescore start` in tmux or screen, or provide a startup script to start namescore at system startup.

## Offline mode
Run `namescore start --offline` to cature dns queries but do not send it to AlphaSOC.
In offline mode rquests won't be send to AlphaSOC api, which also means the events won't be poll to naemscore, so
you won't be albe to indentify threats.
In config you can set option `quereis.failed.file` which will allow to store captured dns quereis in offline mode.
