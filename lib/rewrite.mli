(* should the source IP and port be overwritten, 
   or the destination IP and port?  *)
type direction = Source | Destination 

(** given a lookup table, rewrite direction, and an ip-level frame, 
  * perform any translation indicated by presence in the table
  * on the Cstruct.t .  If the packet should be forwarded, return Some packet,
  * else return None.  (TODO: this doesn't really make sense in the context of a
  * library function; separate out this logic.) 
  * This function is zero-copy and mutates values * in the given Cstruct.  *)
val translate : Lookup.table -> direction -> Cstruct.t -> Cstruct.t option
