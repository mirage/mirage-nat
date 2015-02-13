type protocol = int
type port = int
type t 

val lookup : t -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> (Ipaddr.t * port) option

(* TODO: users aren't going to want to maintain a t of available ports; 
   will need something to manage allocation of free ports for translated IPs *)

val insert : t -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> (Ipaddr.t * port) ->
  t option

val delete : t -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> (Ipaddr.t * port ) ->
  t

val length : t -> int

(* 
val dump_t : t -> unit
*)
val empty : unit -> t
