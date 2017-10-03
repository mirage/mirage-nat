# What is this?

mirage-nat is a library for [network address translation](https://tools.ietf.org/html/rfc2663).  It is intended for use in [MirageOS](https://mirage.io) and makes extensive use of [tcpip](https://github.com/mirage/mirage-tcpip), the network stack used by default in MirageOS unikernels.

# Organization

mirage-nat contains module type definitions for a data store.  Given a data store fulfilling that module type, mirage-nat also can generate modules for useful network address translation operations (e.g. adding entries based on incoming packets and translating packets if matching entries are present).

mirage-nat also contains an implementation of such a data store based on the [lru](https://github.com/pqwy/ocaml-lru) library.  Currently `Mirage_nat_lru` is the only implementation; historical implementations using [irmin](https://github.com/mirage/irmin) as a backing store have been deprecated, but could be revived given sufficient interest.

# Features and Limitations

mirage-nat allows users to add both source NAT (`NAT`) and destination NAT (`Redirect`) rules.

mirage-nat currently supports translations between many addresses on a private IPv4 network and a single public IPv4 address.  It is not capable of translating between IPv4 and IPv6, nor is it capable of translating IPv6 packets between networks.

mirage-nat knows how to translate TCP and UDP packets.  It can also translate some ICMP types:

* timestamp requests and replies
* information requests and replies
* echo requests and replies (in other words, ping should work)

mirage-nat makes no attempt to track connection state and currently does not expire rules based on time's passage.  `Mirage_nat_lru` expires the least recently used rules in response to memory pressure.  In practice, this means rules will stick around as long as there's space for them, with no consideration for whether communication between hosts is still occurring.  Notably, remote hosts which have been contacted by a host on the private network may be able to send traffic back through the NAT long after the host thinks the connection has been terminated.

# Getting Started

The included `example/` directory contains an example MirageOS unikernel which uses `Mirage_nat_lru` to provide source NATting between a private network and a public one.  Try `mirage configure --help` in that directory for information on configuration parameters, and read `unikernel.ml` for more on how it works.

## Network Setup

To get started, you'll need a "public" network (one from which the Internet is accessible) and a "private" network (one which doesn't have outside access; this will be provided by the unikernel once it's online).  Configure the unikernel with the correct public network information, and an IP address on the private network.  For example, to set up a unikernel with a public network on 192.168.3.1/24, and a private 10.0.0.0/24 network, if configured for Xen:

```
mirage configure -t xen --public-ipv4=192.168.3.1/24 --public-ipv4-gateway=192.168.3.254 --private-ipv4=10.0.0.1/24
```

Then follow the usual MirageOS workflow:

```
make depend
make
```

and start the unikernel as appropriate for the hypervisor:

```
sudo xl create simple_nat.xl -c
```

To see more console output, try increasing the log level with the `-l` argument to `mirage configure`.

## Caveats

Please note that only one network interface is supported via solo5 at this time, so trying to run the example with the `-t ukvm` or `-t virtio` targets is likely to be unsatisfying.  The example needs two network interfaces, each on a different network, to do anything interesting.

# Users

[qubes-mirage-firewall](https://github.com/talex5/qubes-mirage-firewall), the unikernel firewall for [QubesOS](https://qubes-os.org), uses mirage-nat to provide network address translation for guest domains.
