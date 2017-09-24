# What is this?

mirage-nat is a library for [network address translation](https://tools.ietf.org/html/rfc2663).  It is intended for use in [MirageOS](https://mirage.io) and makes extensive use of [tcpip](https://github.com/mirage/mirage-tcpip), the network stack used by default in MirageOS unikernels.

# Organization

mirage-nat contains module type definitions for a data store.  Given a data store fulfilling that module type, mirage-nat also can generate modules for useful network address translation operations (e.g. adding entries based on incoming packets and translating packets if matching entries are present).

mirage-nat-hashtable contains an implementation of such a data store based on the [lru](https://github.com/pqwy/ocaml-lru) library.  Currently mirage-nat-hashtable is the only implementation; historical implementations using [irmin](https://github.com/mirage/irmin) as a backing store have been deprecated, but could be revived given sufficient interest.

# Features and Limitations

mirage-nat allows users to add both source NAT (`NAT`) and destination NAT (`Redirect`) rules.

mirage-nat currently supports translations between many addresses on a private IPv4 network and a single public IPv4 address.  It is not capable of translating between IPv4 and IPv6, nor is it capable of translating IPv6 packets between networks.

mirage-nat knows how to translate TCP and UDP packets.  It can also translate some ICMP types:

* timestamp requests and replies
* information requests and replies
* echo requests and replies (in other words, ping should work)

mirage-nat makes no attempt to track connection state and currently does not expire rules based on time's passage.  mirage-nat-hashtable expires the least recently used rules in response to memory pressure.  In practice, this means rules will stick around as long as there's space for them, with no consideration for whether communication between hosts is still occurring.  Notably, remote hosts which have been contacted by a host on the private network may be able to send traffic back through the NAT long after the host thinks the connection has been terminated.

# Users

[qubes-mirage-firewall](https://github.com/talex5/qubes-mirage-firewall), the unikernel firewall for [QubesOS](https://qubes-os.org), uses mirage-nat-hashtable to provide network address translation.
