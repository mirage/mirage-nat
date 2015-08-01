type protocol = int
type port = int
type endpoint = (Ipaddr.t * port)
type mapping = (endpoint * endpoint)
type t 

type mode =
  | Redirect
  | Nat

val lookup : t -> protocol -> source:endpoint -> destination:endpoint ->
  (endpoint * endpoint) option

val insert : t -> protocol -> (mapping * mapping * mapping * mapping) -> t option

val delete : t -> protocol -> endpoint -> endpoint -> endpoint -> endpoint -> t option

val string_of_t : t -> string

val empty : unit -> t
