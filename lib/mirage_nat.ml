type port = Cstruct.uint16
type endpoint = (Ipaddr.V4.t * port)

type error = [`Overlap | `Cannot_NAT | `Untranslated | `TTL_exceeded]

let pp_error f = function
  | `Overlap -> Fmt.string f "Overlapping NAT entry"
  | `Cannot_NAT -> Fmt.string f "Cannot add rule for this packet type"
  | `Untranslated -> Fmt.string f "Packet not translated"
  | `TTL_exceeded -> Fmt.string f "TTL exceeded"

module type S = sig
  type t
  val translate : t -> Nat_packet.t -> (Nat_packet.t, [> `Untranslated | `TTL_exceeded]) result Lwt.t
  val add : t -> Nat_packet.t -> endpoint -> [`NAT | `Redirect of endpoint] -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t
  val reset : t -> unit Lwt.t
end

module type SUBTABLE = sig
  type t

  type transport_channel
  type channel = Ipaddr.V4.t * Ipaddr.V4.t * transport_channel

  val lookup : t -> channel -> channel option Lwt.t
  val insert : t -> (channel * channel) list -> (unit, [> `Overlap]) result Lwt.t
  val delete : t -> channel list -> unit Lwt.t
end

module type TABLE = sig
  type t

  module TCP  : SUBTABLE with type t := t and type transport_channel = port * port
  module UDP  : SUBTABLE with type t := t and type transport_channel = port * port
  module ICMP : SUBTABLE with type t := t and type transport_channel = Cstruct.uint16

  val reset : t -> unit Lwt.t
  (** Remove all entries from the table. *)
end
