include Mirage_nat.S

val empty : tcp_size:int -> udp_size:int -> icmp_size:int -> t Lwt.t
(** [empty ~tcp_size ~udp_size ~icmp_size] is a fresh, empty table with the
    given limits on the number of entries (LRU will be discarded). *)

val pp_summary : t Fmt.t
