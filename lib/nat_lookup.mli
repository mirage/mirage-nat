type protocol = | Udp | Tcp
type port = int
type endpoint = Nat_table.Endpoint.t
type mapping = (endpoint * endpoint)
type t 

type mode =
  | Redirect
  | Nat

val lookup : t -> protocol -> source:endpoint -> destination:endpoint ->
  (endpoint * endpoint) option Lwt.t

val insert : t -> float -> protocol ->
  internal_lookup:mapping -> 
  external_lookup:mapping ->
  internal_mapping:mapping ->
  external_mapping:mapping -> t option Lwt.t

val delete : t -> protocol ->
  internal_lookup:mapping -> external_lookup:mapping -> t Lwt.t

val empty : unit -> t Lwt.t
