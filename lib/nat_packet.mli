type icmp = [
  | `Query of Cstruct.t
  | `Error of Ipv4_packet.t * Cstruct.t * int (* Payload length *)
]
[@@deriving eq]

type t =
  [`IPv4 of Ipv4_packet.t * [ `TCP of Tcp.Tcp_packet.t * Cstruct.t
                            | `UDP of Udp_packet.t * Cstruct.t
                            | `ICMP of Icmpv4_packet.t * icmp
                            ]
  ]

type error

val pp_error : error Fmt.t

val of_ethernet_frame : Cstruct.t -> (t, error) result

val of_ipv4_packet : Cstruct.t -> (t, error) result

val to_cstruct : t -> Cstruct.t list
(** [to_cstruct packet] is the list of cstructs representing [packet].
It currently returns [(ip_header, transport_header, payload)] *)

val into_cstruct : t -> Cstruct.t -> (int, error) result
(** [into_cstruct packet buf] attempts to serialize [packet] into [buf].
On success, it will return the number of bytes written. *)

val pp : [< t] Fmt.t

val equal : t -> t -> bool
