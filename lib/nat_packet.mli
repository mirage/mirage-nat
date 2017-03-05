type t =
  [`IPv4 of Ipv4_packet.t * [ `TCP of Tcp.Tcp_packet.t * Cstruct.t
                            | `UDP of Udp_packet.t * Cstruct.t ]
  ]

type error

val pp_error : error Fmt.t

val of_ethernet_frame : Cstruct.t -> (t, error) result

val of_ipv4_packet : Cstruct.t -> (t, error) result

val to_cstruct : t -> Cstruct.t list
(** [to_cstruct packet] is the list of cstructs representing [packet].
    It currently returns [(ip_header, transport_header, payload)] *)

val pp : t Fmt.t

val equal : t -> t -> bool
