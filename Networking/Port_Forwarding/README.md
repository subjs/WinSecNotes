# Port Forwarding and SOCKS5

Firstly, **Port Forwarding**. This is a server that listens for TCP or UDP traffic on a specified host + port (local host + port) and then simply sends the same data to another specified port(remote host + port).

It is easy to implement, but it is not very flexible. For red teaming, this can be used to connect machine ```A``` <==> ```B``` , if ```B``` normally doesn't allow connections with ```A``` (perhaps it has a firewall rule blocking ```A```'s traffic).
This is done by running the port_forwarder on an intermediary proxy machine (Machine ```P```), and have: ```A``` <==> ```P``` <==> ```B```. You will have to specify, on machine ```P```, which port to listen for ```A```'s traffic and also which host+port to 
send to get to ```B```.

Now the issue with this simple port forwarding is that it is very simple. You need to have a new server for every connection you want to forward. If only there were a more generalized/standardized way to this - where the important routing info is packed in the packet data.

Enter **SOCKS5**. This is a TCP/UDP forwarder that packs the important routing (and authentication) data into a SOCKS5 header. The full specs of how the handshake works is here: https://datatracker.ietf.org/doc/html/rfc1928.

After a specific connection instance finishes its SOCKS5 handshake, then it will forward traffic back and forth just like our basic Port Forwarder. Our basic Port Forwarder, however, is only capable of forwarding one connection to and from a fixed IP+port.
The SOCKS5 proxy server is more flexible - each connection can be forwarded to a different IP+port.


**NOTE**: For a more fully capable SOCKS5 proxy, check out:


[ProxyChain](https://github.com/haad/proxychains) - Linux only

[ligolo](https://github.com/sysdream/ligolo) - Windows, MacOs, Linux

[ligolo-ng](https://github.com/nicocha30/ligolo-ng) - Windows, MacOs, Linux -- Uses TUN interface rather than SOCKS proxy. Faster.

