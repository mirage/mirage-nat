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
