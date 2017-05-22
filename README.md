# Namescore
**Namescore** is a lightweight Linux client used to capture DNS query events from a network and submit them to _api.alphasoc.net_ for processing. The AlphaSOC DNS Analytics Engine quickly identifies security threats within DNS material (e.g. C2 traffic, DNS tunneling, ransomware, and policy violations such as cryptocurrency mining and third-party VPN use).

Upon processing, alert data is returned by Namescore in JSON format, describing the threats and policy violatinons.

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
# go get github.com/alphasoc/namescore.git
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
  account register   Generate an API key via the licensing server
  account status     Show the status of your AlphaSOC API key and license
  listen             Start the DNS sniffer and score live events
  read [file]        Process DNS events stored on disk in PCAP format
  version            Show the Namescore binary version
  help               Provides help and usage instructions

Use "namescore [command] --help" for more information about a given command.
```

## Configuration
Namescore expects to find its configuration file in `/etc/namescore/config.yml`. You can find an example `config.yml` file in the repository's root directory. The file defines the network interface to monitor for DNS traffic, and other variables. If you already have AlphaSOC API key, update the file with your key and place within the `/etc/namescore/` directory. Otherwise, simply run `namescore` which will create the files and prompt you for some details, e.g.

```
# namescore
Provide your details to generate an API key and complete setup.
A valid email address is required to activate the key. 

By performing this request you agree to our Terms of Service and Privacy Policy
(https://www.alphasoc.com/terms-of-service)

Full Name: Joey Bag O'Donuts
Email: joey@example.org

Success! Check your email and click the verification link to activate your API key.
```

## Monitoring scope
Use directives within `/etc/namescore/scope.yml` to define the monitoring scope. DNS requests from the IP ranges within scope will be processed by the AlphaSOC DNS Analytics API, and domains that are whitelisted (e.g. internal trusted domains) will be ignored. Use the `scope.yml` to define the networks and systems that you wish to monitor, and the events to discard, e.g.

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

## Retrieving account status
Use `namescore account status` to return account and AlphaSOC API key details.

## Running Namescore
You may run `namescore listen` in tmux or screen, or provide a startup script to run Namescore on boot.
