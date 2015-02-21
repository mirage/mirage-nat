type protocol = int
type port = int
type t 

val lookup : t -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> 
  ((Ipaddr.t * port) * (Ipaddr.t * port)) option

val insert : t -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> 
  (Ipaddr.t * port) -> (Ipaddr.t * port) -> t option

val delete : t -> protocol -> (Ipaddr.t * port) -> (Ipaddr.t * port) -> 
  (Ipaddr.t * port) -> (Ipaddr.t * port) -> t option

val string_of_t : t -> string

val empty : unit -> t
