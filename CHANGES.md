## v2.2.1 (2020-05-15)
- Also report freed ICMP ports in remove_connections (#40 by @linse @hannesm)

## v2.2.0 (2020-05-04)
- Add remove_connections : t -> Ipaddr.V4.t -> { tcp : int list ; udp : int list }
  to drop all connections from the NAT table for the given IP address. (#39 by @linse @hannesm)

## v2.1.0 (2020-02-18)
- support tcpip 4.1.0, which Ipv4.Fragments interface changed from LRU.M to LRU.F
- Mirage_nat_lru uses as well a LRU.F again
- breaking: Nat_packet.of_ipv4_frame / of_ethernet_frame output a pair of
  `Fragments.t * (t option, error) result`
- all in #37 by @hannesm

## v2.0.0 (2019-12-19)
- support IPv4 fragmentation and reassembly (#36, by @hannesm)
- remove unused TIME and MCLOCK requirements (#33, by @yomimono)
- MirageOS 3.7 support (#34, by @hannesm)

## 1.2.0 (2019-04-15)
- properly support ICMP error handling, enabling path MTU discovery and traceroute (#26, by @linse and @yomimono)
- adapt to lru 0.3.0 and use imperative map interface (#29, by @pqwy)
- update opam files to version 2; remove unused bindings and magic numbers in example unikernels (#25, @hannesm)

## 1.1.0 (2019-03-17)
- Depend on (and require) new `ethernet` and `arp` packages, and the new `tcpip` that goes with them. (#24, by @yomimono)
- Expose and demonstrate a `Nat_packet.into_cstruct` function which is a nicer fit for the new write API for network functions. (#24, by @yomimono)
- Port the build system to Dune. (#24, by @yomimono)

## 1.0.0 (2017-10-05)

- Initial release.
