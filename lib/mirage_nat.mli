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

type time = int64

type error = [
  | `Overlap      (* There is already a translation using this slot. *)
  | `Cannot_NAT   (* It is not possible to make this translation for this type of packet. *)
  | `Untranslated (* There was no matching entry in the NAT table. *)
]

val pp_error : [< error] Fmt.t

module type CLOCK = Mirage_clock_lwt.MCLOCK

module type TIME = Mirage_time_lwt.S

module type S = sig
  type t
  type config

  val empty : config -> t Lwt.t

  (** given a lookup table and an ip-level frame,
    * perform any translation indicated by presence in the table
    * on the Cstruct.t .  If the packet should be forwarded, return Some packet,
    * else return None.
    * This function is zero-copy and mutates values in the given Cstruct.  *)
  val translate : t -> Nat_packet.t -> (Nat_packet.t, [> `Untranslated]) result Lwt.t

  (** given a table, a frame, and a translation IP and port,
    * put relevant entries for the (src_ip, src_port), (dst_ip, dst_port) from the
    * frame and given (xl_ip, xl_port).
      entries will look like:
      ((src_ip, src_port), (dst_ip, dst_port) to
         (xl_ip, xl_port), (dst_ip, dst_port)) and
      ((dst_ip, dst_port), (xl_ip, xl_port)) to
         (dst_ip, dst_port), (src_ip, src_port)).
    * if insertion succeeded, return the new table;
    * otherwise, return an error type indicating the problem. *)
  val add_nat : t -> Nat_packet.t -> endpoint -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t

  (** given a table, a frame from which (src_ip, src_port) and (xl_left_ip,
      xl_left_port) can be extracted (these are source and destination for the
      packet), a translation (xl_left_ip, xl_left_port) pair, and a final
      destination (dst_ip, dst_port) pair, add entries to table of the form:
      ((src_ip, src_port), (xl_left_ip, xl_left_port)) to
           ((xl_right_ip, xl_right_port), (dst_ip, dst_port)) and
      ((dst_ip, dst_port), (xl_right_ip, xl_right_port)) to
           ((xl_left_ip, xl_left_port), (src_ip, src_port)).
      ((xl_ip, xl_right_port), (dst_ip, dst_port)) to (src_ip, src_port).
    * if insertion succeeded, return the new table;
    * otherwise, return an error type indicating the problem. *)
  val add_redirect : t -> Nat_packet.t -> endpoint -> endpoint -> (unit, [> `Overlap | `Cannot_NAT]) result Lwt.t
end

module type Lookup = sig
  type t 
  type config

  val lookup : t -> protocol -> source:endpoint -> destination:endpoint ->
    (int64 * mapping) option Lwt.t

  val insert : t -> time -> protocol -> translation -> (unit, [> `Overlap]) result Lwt.t

  val delete : t -> protocol ->
    internal_lookup:mapping ->
    external_lookup:mapping -> t Lwt.t

  val empty : config -> t Lwt.t
end
