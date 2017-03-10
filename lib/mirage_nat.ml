type port = Cstruct.uint16
type endpoint = (Ipaddr.t * port)

type error = [`Overlap | `Cannot_NAT | `Untranslated | `TTL_exceeded]

let pp_error f = function
  | `Overlap -> Fmt.string f "Overlapping NAT entry"
  | `Cannot_NAT -> Fmt.string f "Cannot add rule for this packet type"
  | `Untranslated -> Fmt.string f "Packet not translated"
  | `TTL_exceeded -> Fmt.string f "TTL exceeded"

type time = int64

module type CLOCK = Mirage_clock_lwt.MCLOCK

module type TIME = Mirage_time_lwt.S

module type S = sig
  type t
  val translate : t -> Nat_packet.t -> (Nat_packet.t, [> `Untranslated | `TTL_exceeded]) result Lwt.t
  val add : t -> now:time -> Nat_packet.t -> endpoint -> [`NAT | `Redirect of endpoint] -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t
  val reset : t -> unit Lwt.t
end

module type SUBTABLE = sig
  type t

  type channel

  val lookup : t -> channel -> (time * channel) option Lwt.t
  val insert : t -> expiry:time -> (channel * channel) list -> (unit, [> `Overlap]) result Lwt.t
  val delete : t -> channel list -> unit Lwt.t
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
