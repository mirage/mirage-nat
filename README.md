Eventually, this will be a module with configurable network address translation capabilities paired with a demonstration Mirage unikernel.

Roadmap:

* stateless demonstration of simple NAT lookup and packet rewriting given initial starting state (ipv4, ipv6 to ipv4)
* configuration changes by outside API, probably HTTP (this can be exposed over vchan in addition to over network)
* listener capable of constructing and destructing NAT table entries according to specified rules
* signpost-compatible checks for device identity against local dns
* more complicated protocol compatibility (e.g. ftp, snmp)
