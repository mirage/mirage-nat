type port = Cstruct.uint16
type endpoint = Ipaddr.t * port
type time = int64

type error = [
  | `Overlap      (* There is already a translation using this slot. *)
  | `Cannot_NAT   (* It is not possible to make this translation for this type of packet. *)
  | `Untranslated (* There was no matching entry in the NAT table. *)
  | `TTL_exceeded (* The packet's time-to-live has run out *)
]

val pp_error : [< error] Fmt.t

module type CLOCK = Mirage_clock_lwt.MCLOCK

module type TIME = Mirage_time_lwt.S

module type S = sig
  type t

  val translate : t -> Nat_packet.t -> (Nat_packet.t, [> `Untranslated | `TTL_exceeded]) result Lwt.t
  (** Given a lookup table and an ip-level packet,
    * perform any translation indicated by presence in the table.
    * If the packet should be forwarded, return the translated packet,
    * else return [Error `Untranslated].
    * The payload in the result shares the Cstruct with the input, so they should be
    * treated as read-only. *)

  val add_nat : t -> Nat_packet.t -> endpoint -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t
  (** Given a table, a frame, and a translation IP and port (i.e. a public
      endpoint on the NAT device),
      insert relevant entries for the (src_ip, src_port), (dst_ip, dst_port) from the
      packet.
      Entries will look like:
      ((src_ip, src_port), (dst_ip, dst_port) to
         (xl_ip, xl_port), (dst_ip, dst_port)) and
      ((dst_ip, dst_port), (xl_ip, xl_port)) to
         (dst_ip, dst_port), (src_ip, src_port)). *)

  val add_redirect : t -> Nat_packet.t -> endpoint -> endpoint -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t
  (** Given a table, a packet from which (src_ip, src_port) and (xl_left_ip,
      xl_left_port) can be extracted (these are source and destination for the
      packet), a translation (xl_left_ip, xl_left_port) pair, and a final
      destination (dst_ip, dst_port) pair, add entries to table of the form:
      ((src_ip, src_port), (xl_left_ip, xl_left_port)) to
           ((xl_right_ip, xl_right_port), (dst_ip, dst_port)) and
      ((dst_ip, dst_port), (xl_right_ip, xl_right_port)) to
           ((xl_left_ip, xl_left_port), (src_ip, src_port)).
      ((xl_ip, xl_right_port), (dst_ip, dst_port)) to (src_ip, src_port). *)

  val reset : t -> unit Lwt.t
  (** Remove all entries from the table. *)
end

module type SUBTABLE = sig
  type t

  type channel

  val lookup : t -> channel -> (time * channel) option Lwt.t
  (** [lookup t channel] is [Some (expiry, translated_channel)] - the new endpoints
      that should be applied to a packet using [channel] - or [None] if no entry for [channel] exists.
      [expiry] is an absolute time-stamp. *)

  val insert : t -> time -> (channel * channel) list -> (unit, [> `Overlap]) result Lwt.t
  (** [insert t time translations] adds the given translations to the table.
      Each translation is a pair [input, target] - packets with channel [input] should be
      rewritten to have channel [output].
      It returns an error if the new entries would overlap with existing entries.
      [time] is the absolute time-stamp of the desired expiry time. *)

  val delete : t -> channel list -> unit Lwt.t
  (** [delete t sources] removes the entries mapping [sources], if they exist. *)
end

module type TABLE = sig
  type t

  module TCP  : SUBTABLE with type t := t and type channel = endpoint * endpoint
  (** A TCP channel is identified by the source and destination endpoints. *)

  module UDP  : SUBTABLE with type t := t and type channel = endpoint * endpoint
  (** A UDP channel is identified by the source and destination endpoints. *)

  module ICMP : SUBTABLE with type t := t and type channel = Ipaddr.t * Ipaddr.t * Cstruct.uint16
  (** An ICMP query is identified by the source and destination IP addresses and the ICMP ID. *)

  val reset : t -> unit Lwt.t
  (** Remove all entries from the table. *)
end
