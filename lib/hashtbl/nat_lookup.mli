open Nat_types

module type S = sig
  type t 

  val lookup : t -> protocol -> source:endpoint -> destination:endpoint ->
    (int64 * mapping) option Lwt.t

  val insert : t -> int -> protocol -> translation -> t option Lwt.t

  val delete : t -> protocol ->
    internal_lookup:mapping ->
    external_lookup:mapping -> t Lwt.t

  val empty : unit -> t Lwt.t
end

module Make(Clock: CLOCK)(Time: TIME) : sig
  include S
end
