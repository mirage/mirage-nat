type t =
  [`IPv4 of Ipv4_packet.t * [ `TCP of Tcp.Tcp_packet.t * Cstruct.t
                            | `UDP of Udp_packet.t * Cstruct.t
                            | `ICMP of Icmpv4_packet.t * Cstruct.t
                            ]
  ]

type error

val icmp_type : Icmpv4_packet.t -> [ `Query | `Error ]

val pp_error : error Fmt.t

val of_ethernet_frame : Fragments.Cache.t -> now:int64 -> Cstruct.t ->
  Fragments.Cache.t * (t option, error) result

val of_ipv4_packet : Fragments.Cache.t -> now:int64 -> Cstruct.t ->
  Fragments.Cache.t * (t option, error) result

val to_cstruct : ?mtu:int -> t -> (Cstruct.t list, error) result
(** [to_cstruct packet] is the list of cstructs representing [packet].
    It returns a list of fragments to be sent, or an error if fragmentation
    was needed, but disallowed by the provided ip header. *)

val into_cstruct : t -> Cstruct.t -> (int * Cstruct.t list, error) result
(** [into_cstruct packet buf] attempts to serialize [packet] into [buf].
    On success, it will return the number of bytes written and a list of further
    fragments to be written. *)

val pp : [< t] Fmt.t

val equal : t -> t -> bool
