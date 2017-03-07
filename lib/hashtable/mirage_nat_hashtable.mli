module Make(Clock: Mirage_nat.CLOCK)(Time: Mirage_nat.TIME) : sig
  include Mirage_nat.S

  val empty : Clock.t -> t Lwt.t
  (** [empty clock] is a fresh, empty table. *)
end
