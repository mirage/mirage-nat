type port = Cstruct.uint16
type endpoint = (Ipaddr.V4.t * port)

type error = [`Overlap | `Cannot_NAT | `Untranslated | `TTL_exceeded]

let pp_error f = function
  | `Overlap -> Fmt.string f "Overlapping NAT entry"
  | `Cannot_NAT -> Fmt.string f "Cannot add rule for this packet type"
  | `Untranslated -> Fmt.string f "Packet not translated"
  | `TTL_exceeded -> Fmt.string f "TTL exceeded"

type ports = {
  tcp : port list ;
  udp : port list ;
  icmp : port list ;
}

module type S = sig
  type t
  val remove_connections : t -> Ipaddr.V4.t -> ports
  val translate : t -> Nat_packet.t -> (Nat_packet.t, [> `Untranslated | `TTL_exceeded]) result
  val is_port_free : t -> [ `Udp | `Tcp | `Icmp ] -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> dst_port:int -> bool
  val add : t -> Nat_packet.t -> Ipaddr.V4.t -> (unit -> int) -> [`NAT | `Redirect of endpoint] -> (unit, [> `Overlap | `Cannot_NAT]) result
  val reset : t -> unit
end

module type SUBTABLE = sig
  type t

  type transport_channel
  type channel = Ipaddr.V4.t * Ipaddr.V4.t * transport_channel

  val lookup : t -> channel -> channel option
  val insert : t -> (channel * channel) list -> (unit, [> `Overlap]) result
  val delete : t -> channel list -> unit
end

module type TABLE = sig
  type t

  module TCP  : SUBTABLE with type t := t and type transport_channel = port * port
  module UDP  : SUBTABLE with type t := t and type transport_channel = port * port
  module ICMP : SUBTABLE with type t := t and type transport_channel = Cstruct.uint16

  val reset : t -> unit
  (** Remove all entries from the table. *)

  val remove_connections : t -> Ipaddr.V4.t -> ports

  val is_port_free : t -> [ `Udp | `Tcp | `Icmp ] -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> dst_port:int -> bool
end
