include Mirage_nat.S

val empty : unit -> t Lwt.t
(** [empty ()] is a fresh, empty table. *)
