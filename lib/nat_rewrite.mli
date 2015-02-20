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
  * if insertion succeeded, return the new table;
  * otherwise, return an error type indicating the problem. *)
val make_entry : Nat_lookup.t -> Cstruct.t -> Ipaddr.t -> int -> insert_result
