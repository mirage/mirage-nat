type 'a layer = Cstruct.t
type ethernet
type ip
type transport

(* given an ip packet, fish out the src and dst ip *)
val addresses_of_ip : ip layer -> (Ipaddr.t * Ipaddr.t)

(* given an ip packet, fish out the transport-layer protocol number *)
val proto_of_ip : ip layer -> int

(* given a transport-layer packet, fish out the transport-layer source and
   destination ports *)
val ports_of_transport : transport layer -> (int * int)

(* attempt to decompose a frame into Cstructs representing the ethernet, ip, and
  tx layers.  each cstruct maintains a view into those above it (i.e., the
   ethernet cstruct's length is not set to the length of the ethernet header).
*)
val layers : Cstruct.t -> (ethernet layer * ip layer * transport layer) option

(* given an ethernet layer with some space for payload and a desired ip payload,
   do some sanity checking and potentially give back a packet ready for
   transmission *)
(* (this is a composition function, not a decomposition function... *)
val ethip_headers : (ethernet layer * ip layer) -> Cstruct.t option
