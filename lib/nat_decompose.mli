type 'a layer
type ethernet
type ip
type transport
type payload

(* given an ip packet, fish out the src and dst ip *)
val addresses_of_ip : ip layer -> (Ipaddr.t * Ipaddr.t)

(* given an ip packet, fish out the transport-layer protocol number *)
val proto_of_ip : ip layer -> Cstruct.uint8

(* given a transport-layer packet, fish out the transport-layer source and
   destination ports *)
val ports_of_transport : transport layer -> (int * int)

(* attempt to decompose a frame into Cstructs representing the ethernet, ip,
   tx, and payload (potentially empty) layers.
   each cstruct maintains a view into those above it (i.e., the
   ethernet cstruct's length is not set to the length of the ethernet header).
*)
val layers : Cstruct.t ->
  (ip layer * transport layer * payload layer) option

(* given an ethernet layer with some space for payload and a desired ip payload,
   do some sanity checking and potentially give back a packet ready for
   transmission *)
(* (this is a composition function, not a decomposition function) *)
val ethip_headers : (ethernet layer * ip layer) -> Cstruct.t option

(* given a function for recalculating transport-layer checksums and a set of
   layers, recalculate and set checksum for valid-looking udp or tcp packets.

   Return a tuple of (ethernet and IP headers only, transport layer and payload)
   for dispatch to I.write .
*)

val finalize_packet : 
  (ethernet layer * ip layer * transport layer * payload layer) -> (Cstruct.t * Cstruct.t)

(* set the ethernet source address to the provided MAC address *)
val set_smac : ethernet layer -> Macaddr.t -> ethernet layer

(* support for direct rewriting of packets *)
val rewrite_ip : bool -> ip layer -> (Ipaddr.t * Ipaddr.t) -> unit

val rewrite_port : transport layer -> (int * int) -> unit

val decrement_ttl : ip layer -> unit

val recalculate_ip_checksum : ip layer -> transport layer -> unit

val compare : 'a layer -> 'a layer -> int
