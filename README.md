# autogw

Automatically resolve domain according to the config and act as a proxied gateway.

Autogw use a Redis Server to store all domain list and IP filter.

Autogw does two things:

1. Proxy a DNS query
2. Relay the incoming TCP connection according to the DNS query result.

For Example:

1. We have a soft CentOS 7 gateway with IP address: 192.168.1.1, and we run autogw on it.
2. We config the dhcpd server to tell all client to use dns server 192.168.1.1(which is autogw)
3. We set *google.com to use a socks5 proxy at 192.168.1.1:8090, and use up level dns server 8.8.8.8
4. Client open www.google.com in browser, the browser first will try to resolve the domain, and send request to autogw
5. autogw will first parse the DNS query package and find the query domain is www.google.com, which match the prevoius setting rule, then it will use the socks5 proxy to redirect the package to 8.8.8.8
6. After receiving the response from 8.8.8.8, autogw will parse the package to get all CNAME and A records
7. autogw will create an iptable rule for all A records' IP, and save the rule in Redis Server
8. and also, autogw will create a new rule for the CNAME result with same proxy server.
9. Then return the orignial response package to the browser, the browser then will try to build a connection to the server
10. The gateway's iptable will find a rule for the target Google's server, and redirect the connection to autogw's proxy port
11. autogw then will use the proxy to connect to the target and make a tcp relay between original browser connection and target server.

```sequence
Browser(Client)->DNS Server(autogw): Query www.google.com
DNS Server(autogw)->Uplevel DNS Server(8.8.8.8): Redirect use socks5 proxy
Uplevel DNS Server(8.8.8.8)->DNS Server(autogw): Parse and get A/CNAME records
Note right of DNS Server(autogw): Create iptable rule
DNS Server(autogw)->Browser(Client): Result of DNS
Browser(Client)->Gateway: Connect to Google(172.217.6.36)
Gateway->autogw: Match iptable rule and redirect to autogw
autogw->Google.com: Use the proxy to connect
Google.com->autogw: Normal response
autogw->Gateway: Normal response
Gateway->Browser(Client): Normal response

```

Everything for the client is transparent. It knows nothing.

Usually, we use autogw to connect two or more different network and provides a transparent network envorinment for all the clients.

## Dependences

* [`PEUtils`][https://github.com/littlepush/PEUtils]
* [`PECoTask`][https://github.com/littlepush/PECoTask]
* [`PECoNet`][https://github.com/littlepush/PECoNet]

## Install

```
make && make install
```



## Usage

```
autogw [OPTION]...
```

* `-r, --redis`: Redis server url
* `-p, --gw-port`: Gateway redirect port, default is 4300
* `-n, --gw-name`: NAT chain name
* `-m, --master`: Uplevel dns query server, default is 114.114.114.114, if not specified a port, will use 53
* `-f, --initfw`: Firewall initial script, used to build the basic iptables
* `--enable-conet-trace`: *only in debug version*, enable log trace of libconet
* `--enable-cotask-trace`: *only in debug version*, enable log trace of libcotask

## Commands

autogw will use `BLPOP` to monitor the command queue in Redis server.

### Add a new Domain Rule

```
BRPUSH autogw.command addqs@<domain>@<dns_server>[@<socks5_address>]
```

* `<domain>` can be one of the following:
  * `*key*`: if a query domain contains the key
  * `*key`: if a query domain is end with the key
  * `key*`: if a query domain is begin with the key
  * `key`: if a query domain is equal to the key
* `<dns_server>` must be an IP address
* `<socks5_address>` is an optional argument, if not set, autogw will redirect the package to dns_server use UDP connection.

### Delete a Domain Rule

```
BRPUSH autogw.command delqs@<domain>
```

The `<domain>` must be the same as when it was added.

### Add an IP Rule

```
BRPUSH autogw.command addip@<ip>@<socks5_address>
```

Tell autogw to create an iptable rule to redirect a certain IP address, no matter which domain it belongs.

Delete an IP Rule

```
BRPUSH autogw.command delip@<ip>
```

Tell autogw to delete the IP's iptable rule.

**Note**: autogw will add this rule back if the some domain's DNS records contain the IP.



## Initial iptables

Usually we use the following script to create a gateway and init the iptables

```bash
#! /bin/bash

echo "1" > /proc/sys/net/ipv4/ip_forward

I_FACE=eth1	# LAN side interface
O_FACE=eth0	# WAN side interface
GATEWAY_IP=<My_LAN_Side_IP>
LAN_MASK=<My_LAN_Side_NetMask>  # 192.168.1.0/24
CHAIN_NAME=<My_NAT_Chain_Name>

iptables -t nat -F
iptables -t mangle -F
iptables -t nat -X
iptables -F
iptables -X

iptables -t nat -N $CHAIN_NAME

iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

iptables -A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $I_FACE -o $O_FACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $I_FACE -o $O_FACE -j ACCEPT

# Open Ports
#iptables -A INPUT -p tcp -m tcp -s <INTERNAL_ADDRESS> --dport <OPEN_PORT> -j ACCEPT

## Redirect Port
#iptables -A FORWARD -d <TARGET_IP> -p tcp -m tcp --dport <TARGET_PORT> -j ACCEPT
#iptables -t nat -A PREROUTING -i $O_FACE -p tcp -m tcp --dport <TARGET_PORT> -j DNAT --to-destination <TARGET_IP>:<TARGET_PORT>

# Create a gateway nat chain

iptables -t nat -A PREROUTING -p tcp -j $CHAIN_NAME
iptables -t nat -A PREROUTING -p udp -j $CHAIN_NAME
# ignore root's outgoing traffic
iptables -t nat -A OUTPUT -m owner --uid-owner root -j RETURN
iptables -t nat -A OUTPUT -p tcp -j $CHAIN_NAME
iptables -t nat -A OUTPUT -p udp -j $CHAIN_NAME

iptables -t nat -A POSTROUTING -o $O_FACE -j MASQUERADE
iptables -t nat -A POSTROUTING -o $I_FACE ! -p esp -j SNAT --to-source $GATEWAY_IP
# Ignore LAN side connection
iptables -t nat -A $CHAIN_NAME -d $LAN_MASK -j RETURN
# Ignore localhost connection
iptables -t nat -A $CHAIN_NAME -d 127.0.0.1/32 -j RETURN

```



## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <https://www.gnu.org/licenses/>.