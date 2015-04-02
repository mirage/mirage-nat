(* should the source IP and port be overwritten,
   or the destination IP and port?  *)
type direction = Source | Destination

type insert_result =
  | Ok of Nat_lookup.t
  | Overlap
  | Unparseable

(* phantom types for Cstructs, so type system can help us keep them straight *)
type transport
type ethernet
type ip
type 'a layer

(** given a lookup table, rewrite direction, and an ip-level frame,
  * perform any translation indicated by presence in the table
  * on the Cstruct.t .  If the packet should be forwarded, return Some packet,
  * else return None.  
  * This function is zero-copy and mutates values in the given Cstruct.  *)
val translate : Nat_lookup.t -> direction -> Cstruct.t -> Cstruct.t option

(** given a table, a frame, and a translation IP and port,
  * put relevant entries for the (src_ip, src_port), (dst_ip, dst_port) from the
  * frame and given (xl_ip, xl_port).
    entries will look like:
    ((src_ip, src_port), (dst_ip, dst_port) to
       (xl_ip, xl_port), (dst_ip, dst_port)) and
    ((dst_ip, dst_port), (xl_ip, xl_port)) to
       (dst_ip, dst_port), (src_ip, src_port)).
  * if insertion succeeded, return the new table;
  * otherwise, return an error type indicating the problem. *)
val make_nat_entry : Nat_lookup.t -> Cstruct.t -> Ipaddr.t -> int -> insert_result

(** given a table, a frame from which (src_ip, src_port) and (xl_left_ip,
    xl_left_port) can be extracted (these are source and destination for the
    packet), a translation (xl_left_ip, xl_left_port) pair, and a final
    destination (dst_ip, dst_port) pair, add entries to table of the form:
    ((src_ip, src_port), (xl_left_ip, xl_left_port)) to 
         ((xl_right_ip, xl_right_port), (dst_ip, dst_port)) and
    ((dst_ip, dst_port), (xl_right_ip, xl_right_port)) to 
         ((xl_left_ip, xl_left_port), (src_ip, src_port)).
    ((xl_ip, xl_right_port), (dst_ip, dst_port)) to (src_ip, src_port).
  * if insertion succeeded, return the new table;
  * otherwise, return an error type indicating the problem. *)
val make_redirect_entry : Nat_lookup.t -> Cstruct.t -> (Ipaddr.t * int) 
  -> (Ipaddr.t * int) -> insert_result

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

(* attempt to decompose an ethernet frame into just the ethernet and ip headers.
*)
val ethip_headers : (ethernet layer * ip layer) -> Cstruct.t option

(* support for direct rewriting of packets *)
val rewrite_ip : bool -> ip layer -> direction -> (Ipaddr.t * Ipaddr.t) -> unit

val rewrite_port : transport layer -> direction -> (int * int) -> unit
