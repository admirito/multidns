# multidns

multidns will relay your DNS requsts to several DNS servers and
returns the first answer.

You can also specify an invalid address e.g. 10.10.34.34. If the
answer was 10.10.34.34 the program will continue to try other DNS
servers to find an answer that is not 10.10.34.34.

If you put an `x` character before the address of a DNS server
e.g. `x8.8.8.8:53` the request and its response will be encrypted with
a symmetrical encyption algorithm--that applying the same encryption
algorithm twice will decode to the first input. So if you relay your
DNS requst twice through two instances of this program with `x`
prefixes, the result will be a normal DNS server. But the traffic
between the two program instances will be encrypted. The encryption
algorithm is not secure at all but it is highly possible that it can
fool your government censorship devices.

By default multidns will listen on 127.0.0.7 udp port 53.

### Example Usage:

Standalone Usage:

```
sudo multidns 192.168.1.1 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220
```

Use multiple multidns instances with encryption:

On your local machine:

```
multidns 192.168.1.1 8.8.8.8 x11.22.33.44:5353
```

On your remote machine with 11.22.33.44 IP address:

```
multidns -b0.0.0.0:5353 x8.8.8.8 x208.67.222.222
```
