type protocol = int
type port = int
type t
type table = ((Ipaddr.t * port * protocol), (Ipaddr.t * port)) Hashtbl.t

val t_of_strings : (string * port) -> (string * port) -> protocol -> t
val lookup : table -> protocol -> Ipaddr.t -> port -> (Ipaddr.t * port) option

(* TODO: users aren't going to want to maintain a table of available ports; 
   will need something to manage allocation of free ports for translated IPs *)

(* TODO: it is currently possible for this to silently fail if updating the
   table as requested would result in an inconsistent state; some indication of
   failure should be provided *)
val insert : table -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) ->
  table

val delete : table -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port ) ->
  table

val empty : unit -> table
