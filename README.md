## Synopsis
**Namescore** project aim to provide lightweight and portable client which would provide online analysis of **DNS** requests to identify threats. 
To compile **libpcap-dev** is needed.

## Config file

Configuration file can be created by running **namescore register command**. This file contains two important parameters:

-  *interface* -  network interface which is used to sniff DNS packets from.
- *key* -  unique client API key 

Example:
```
interface = "eth0"
key = "2d18a990c0587b2078fbab5faa84be02"
```

## Whitelist file
This file provides possibility to whitelist specific domains and source IPs.
The file contains two configuration sections:

- *networks* - List of networks. If source IP of DNS request is in one of provided networks or is equal to one of IPs it will be excluded from analysis. 
- *domains* - list of domains which should be excluded from analysis. If domain starts with \* filter with match any subdomain as well.

Example:
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
*namescore status* gives possibility to quickly check the most important parameters and diagnose basic problems.

![status jpg ](https://github.com/alphasoc/namescore/blob/master/status.jpg)

## Tests
Be aware that tests require higher privileges.