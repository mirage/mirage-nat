type transport = | Tcp of (Tcp.Tcp_packet.t * Cstruct.t)
                 | Udp of (Udp_packet.t * Cstruct.t)
                 | Icmp of (Icmpv4_packet.t * Cstruct.t)

type network = | Ipv4 of (Ipv4_packet.t * Cstruct.t)
               | Ipv6 of (Cstruct.t * Cstruct.t)
               | Arp of Arpv4_packet.t

type decomposed =
  { ethernet : Ethif_packet.t * Cstruct.t;
    network : network;
    transport : transport option;
}

val decompose : Cstruct.t -> (decomposed, string) Result.result

val ports : transport option -> (Mirage_nat.protocol * transport * Cstruct.uint8 * Cstruct.uint8) option

(* TODO: in error cases, rewrite_packet should return an ICMP reject message to send back to the packet originator, rather than just a string error *)
val rewrite_packet :
  Nat_packet.t ->
  src:(Ipaddr.V4.t * Mirage_nat.port) -> dst:(Ipaddr.V4.t * Mirage_nat.port) ->
  (Nat_packet.t, string) Result.result
