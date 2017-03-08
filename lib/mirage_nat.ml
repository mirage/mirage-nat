type protocol =
  | Udp
  | Tcp
  | Icmp

type port = Cstruct.uint16
type endpoint = (Ipaddr.t * port)
type mapping = (endpoint * endpoint)

type translation = {
  internal_lookup: mapping;
  external_lookup: mapping;
  internal_mapping: mapping;
  external_mapping: mapping
}

type mode =
  | Redirect
  | Nat

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
  val add_nat : t -> Nat_packet.t -> endpoint -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t
  val add_redirect : t -> Nat_packet.t -> endpoint -> endpoint -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t
  val reset : t -> unit Lwt.t
end

module type Lookup = sig
  type t 

  val lookup : t -> protocol -> source:endpoint -> destination:endpoint ->
    (int64 * mapping) option Lwt.t

  val insert : t -> time -> protocol -> translation -> (unit, [> `Overlap]) result Lwt.t

  val delete : t -> protocol ->
    internal_lookup:mapping ->
    external_lookup:mapping -> unit Lwt.t

  val reset : t -> unit Lwt.t
end
