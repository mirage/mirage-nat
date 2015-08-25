open Sexplib.Std

type direction = | Source | Destination

type protocol = | Udp | Tcp
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

type translate_result =
  | Translated
  | Untranslated

module type CLOCK = sig
  val now : unit -> int64
end

module type TIME = sig
  val sleep : float -> unit Lwt.t
end
