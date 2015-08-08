type protocol = | Udp | Tcp
type port = int
type endpoint = Nat_table.Endpoint.t
type mapping = (endpoint * endpoint)

type mode =
  | Redirect
  | Nat

module type S = sig
  module I : Irmin.BASIC
  type t 

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
end

module Make(I : Irmin.S_MAKER) : sig
  include S
  val store_of_t : t -> I.t
end
