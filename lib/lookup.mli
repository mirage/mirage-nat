type protocol = int
type port = int
type table = (protocol * (Ipaddr.t * port) * (Ipaddr.t * port), (Ipaddr.t *
                                                                 port)) Hashtbl.t

val lookup : table -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> (Ipaddr.t * port) option

(* TODO: users aren't going to want to maintain a table of available ports; 
   will need something to manage allocation of free ports for translated IPs *)

val insert : table -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> (Ipaddr.t * port) ->
  table option

val delete : table -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> (Ipaddr.t * port ) ->
  table

val length : table -> int

(* 
val dump_table : table -> unit
*)
val empty : unit -> table
