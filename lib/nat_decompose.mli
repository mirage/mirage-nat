type 'a layer = Cstruct.t
type protocol = int
type ethernet
type ip
type transport
type payload

(* given an ip packet, fish out the src and dst ip *)
val addresses_of_ip : ip layer -> (Ipaddr.t * Ipaddr.t)

(* given an ip packet, fish out the transport-layer protocol number *)
val proto_of_ip : ip layer -> protocol

(* given a transport-layer packet, fish out the transport-layer source and
   destination ports *)
val ports_of_transport : transport layer -> (int * int)

val ip_and_above_of_frame : Cstruct.t -> Cstruct.t option

val transport_and_above_of_ip : Cstruct.t -> Cstruct.t option

val payload_of_transport : protocol -> Cstruct.t -> Cstruct.t option

(* attempt to decompose a frame into Cstructs representing the ethernet, ip,
   tx, and payload (potentially empty) layers.
   each cstruct maintains a view into those above it (i.e., the
   ethernet cstruct's length is not set to the length of the ethernet header).
*)
val layers : Cstruct.t ->
  (ethernet layer * ip layer * transport layer * payload layer) option

(* given an ethernet layer with some space for payload and a desired ip payload,
   do some sanity checking and potentially give back a packet ready for
   transmission *)
(* (this is a composition function, not a decomposition function... *)
val ethip_headers : (ethernet layer * ip layer) -> Cstruct.t option
