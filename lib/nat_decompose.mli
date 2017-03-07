(* TODO: in error cases, rewrite_packet should return an ICMP reject message to send back to the packet originator, rather than just a string error *)
val rewrite_packet :
  Nat_packet.t ->
  src:(Ipaddr.V4.t * Mirage_nat.port) -> dst:(Ipaddr.V4.t * Mirage_nat.port) ->
  (Nat_packet.t, string) Result.result
