open Nat_types

module type S = sig
  module I : Irmin.BASIC
  type t 

  val lookup : t -> protocol -> source:endpoint -> destination:endpoint ->
    (endpoint * endpoint) option Lwt.t

  val insert : t -> int -> protocol -> translation -> t option Lwt.t

  val delete : t -> protocol ->
    internal_lookup:mapping -> external_lookup:mapping -> t Lwt.t

  val empty : Irmin.config -> t Lwt.t
end

module Make(I : Irmin.S_MAKER)(Clock: CLOCK)(Time: TIME) : sig
  include S
  val store_of_t : t -> I.t
end
