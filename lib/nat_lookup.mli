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

val insert : t -> protocol ->
  internal_lookup:mapping -> 
  external_lookup:mapping ->
  internal_mapping:mapping ->
  external_mapping:mapping -> t option

(* TODO: this signature looks weird next to insert *)
val delete : t -> protocol -> endpoint -> endpoint -> endpoint -> endpoint -> t option

val string_of_t : t -> string

val empty : unit -> t
