(* should the source IP and port be overwritten,
   or the destination IP and port?  *)
type direction = Source | Destination

type insert_result =
  | Ok of Nat_lookup.t
  | Overlap
  | Unparseable

(** given a lookup table, rewrite direction, and an ip-level frame,
  * perform any translation indicated by presence in the table
  * on the Cstruct.t .  If the packet should be forwarded, return Some packet,
  * else return None.  (TODO: this doesn't really make sense in the context of a
  * library function; separate out this logic.)
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

(** given a table, a frame, and a translation IP and port, 
  * put relevant entries for the (src_ip, src_port), (dst_ip, dst_port) from the
  * frame (xl_ip, xl_port) (xl_right_port), depending on the mode argument.
    entries will look like:
    ((src_ip, src_port), (xl_left_ip, xl_left_port)) to 
         ((xl_right_ip, xl_right_port), (dst_ip, dst_port)) and
    ((dst_ip, dst_port), (xl_right_ip, xl_right_port)) to 
         ((xl_left_ip, xl_left_port), (src_ip, src_port)).
    ((xl_ip, xl_right_port), (dst_ip, dst_port)) to (src_ip, src_port).
  * if insertion succeeded, return the new table;
  * otherwise, return an error type indicating the problem. *)
val make_redirect_entry : Nat_lookup.t -> Cstruct.t -> (Ipaddr.t * int) 
  -> (Ipaddr.t * int) -> insert_result

(* given an ethernet-and-above frame, fish out the src and dst ip *)
val ips_of_frame : Cstruct.t -> (Ipaddr.t * Ipaddr.t) option

(* given an ethernet-and-above frame, fish out the transport-layer protocol *)
val proto_of_frame : Cstruct.t -> int option

(* given an ethernet-and-above frame, fish out the transport-layer source and
   destination ports *)
val ports_of_frame : Cstruct.t -> (int * int) option

(* attempt to decompose a frame into Cstructs representing the ethernet, ip, and
  tx layers.  each cstruct maintains a view into those above it (i.e., the
   ethernet cstruct's length is not set to the length of the ethernet header).
*)
val layers : Cstruct.t -> (Cstruct.t * Cstruct.t * Cstruct.t) option

(* support for direct rewriting of packets *)
val rewrite_ip : bool -> Cstruct.t -> direction -> (Ipaddr.t * Ipaddr.t) -> unit

val rewrite_port : Cstruct.t -> direction -> (int * int) -> unit
