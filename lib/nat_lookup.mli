open Nat_types

module type S = sig
  module I : Irmin.S
  type t 

  val lookup : t -> Nat_table.Key.protocol ->
    source:Nat_table.Endpoint.t ->
    destination:Nat_table.Endpoint.t ->
    mapping option Lwt.t

  val insert : t -> int -> Nat_table.Key.protocol -> translation -> t option Lwt.t

  val delete : t -> Nat_table.Key.protocol ->
    internal_lookup:Nat_table.Endpoint.mapping ->
    external_lookup:Nat_table.Endpoint.mapping -> t Lwt.t

  val empty : Irmin.config -> t Lwt.t
end

module Make(I : Irmin.S_MAKER)(Clock: CLOCK)(Time: TIME) : sig
  include S
  val store_of_t : t -> I.t
end
