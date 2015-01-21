type protocol = int
type port = int
type t
type table = ((Ipaddr.t * port * protocol), (Ipaddr.t * port)) Hashtbl.t

val t_of_strings : (string * port) -> (string * port) -> protocol -> t
val lookup : table -> protocol -> Ipaddr.t -> port -> (Ipaddr.t * port) option

(* TODO: users aren't going to want to maintain a table of available ports; 
   will need something to manage allocation of free ports for translated IPs *)
(* TODO: this will currently silently overwrite (optimistically, "update")
   existing bindings *)
(* TODO: of course this is a huge problem if, say, you insert (6,
   192.168.1.1, 3000), (10.1.1.1, 6667) and then insert (6, 10.1.1.1, 6667),
   (192.168.5.12) - you get a chain of mappings instead of a pair as desired *)
val insert : table -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) ->
  table

val delete : table -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port ) ->
  table

val empty : unit -> table
