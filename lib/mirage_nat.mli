type port = Cstruct.uint16
type endpoint = Ipaddr.V4.t * port

type error = [
  | `Overlap      (* There is already a translation using this slot. *)
  | `Cannot_NAT   (* It is not possible to make this translation for this type of packet. *)
  | `Untranslated (* There was no matching entry in the NAT table. *)
  | `TTL_exceeded (* The packet's time-to-live has run out *)
]

val pp_error : [< error] Fmt.t

type ports = {
  tcp : port list ;
  udp : port list ;
  icmp : port list ;
}

module type S = sig
  type t

  val remove_connections : t -> Ipaddr.V4.t -> ports
  (** [remove_connections t ip] removes all connections of [ip] in [t]. *)

  val translate : t -> Nat_packet.t ->
    (Nat_packet.t, [> `Untranslated | `TTL_exceeded]) result
  (** Given a lookup table and an ip-level packet, perform any translation
      indicated by presence in the table.

      If the packet should be forwarded, return the translated packet,
      else return [Error `Untranslated].
      The payload in the result shares the Cstruct with the input, so they should be
      treated as read-only. *)

  val is_port_free : t -> [ `Udp | `Tcp | `Icmp ] -> src:Ipaddr.V4.t ->
    dst:Ipaddr.V4.t -> src_port:int -> dst_port:int -> bool
  (** [is_port_free t protocol ~src ~dst ~src_port ~dst_port] is true if it is
      not taken yet. *)

  val add : t -> Nat_packet.t -> Ipaddr.V4.t -> (unit -> int option) ->
    [`NAT | `Redirect of endpoint] -> (unit, [> `Overlap | `Cannot_NAT]) result
  (** [add t packet xl_host port_generator mode] adds an entry to the table to
      translate packets on [packet]'s channel according to [mode], and another
      entry to translate the replies back again. The [port_generator] may be
      called multiple times (at most 100 times) to find a free port.

      If [mode] is [`NAT] then the entries will be of the form:

      (packet.src -> packet.dst) becomes (xl_endpoint -> packet.dst)
      (packet.dst -> xl_endpoint) becomes (packet.dst -> packet.src)

      If [mode] is [`Redirect new_dst] then
      the entries will be of the form:

      (packet.src -> packet.dst) becomes (xl_endpoint -> new_dst)
      (new_dst -> xl_endpoint) becomes (packet.dst -> packet.src)

      In this case, [packet.dst] will typically be an endpoint on the
      NAT itself, to ensure all packets go via the NAT.

      Returns [`Overlap] if the new entries would partially overlap with an existing
      entry.

      Returns [`Cannot_NAT] if the packet has a non-Global/Organization source or destination,
      or is an ICMP packet which is not a query.
  *)

  val reset : t -> unit
  (** Remove all entries from the table. *)
end

module type SUBTABLE = sig
  type t

  type transport_channel
  type channel = Ipaddr.V4.t * Ipaddr.V4.t * transport_channel

  val lookup : t -> channel -> channel option
  (** [lookup t channel] is [Some (expiry, translated_channel)] - the new endpoints
      that should be applied to a packet using [channel] - or [None] if no entry for [channel] exists.
      [expiry] is an absolute time-stamp. *)

  val insert : t -> (channel * channel) list -> (unit, [> `Overlap]) result
  (** [insert t ~expiry translations] adds the given translations to the table.
      Each translation is a pair [input, target] - packets with channel [input] should be
      rewritten to have channel [output].
      It returns an error if the new entries would overlap with existing entries.
      [expiry] is the absolute time-stamp of the desired expiry time. *)

  val delete : t -> channel list -> unit
  (** [delete t sources] removes the entries mapping [sources], if they exist. *)
end

module type TABLE = sig
  type t

  module TCP  : SUBTABLE with type t := t and type transport_channel = port * port
  (** A TCP channel is identified by the source and destination ports. *)

  module UDP  : SUBTABLE with type t := t and type transport_channel = port * port
  (** A UDP channel is identified by the source and destination ports. *)

  module ICMP : SUBTABLE with type t := t and type transport_channel = Cstruct.uint16
  (** An ICMP query is identified by the ICMP ID. *)

  val reset : t -> unit
  (** Remove all entries from the table. *)

  val remove_connections : t -> Ipaddr.V4.t -> ports
  (** Remove all connections from and to the given IP address. *)

  val is_port_free : t -> [ `Udp | `Tcp | `Icmp ] -> src:Ipaddr.V4.t ->
    dst:Ipaddr.V4.t -> src_port:int -> dst_port:int -> bool
  (** [is_port_free t protocol ~src ~dst ~src_port ~dst_port] is true if it is
      not taken yet. *)
end
