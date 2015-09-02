open Nat_types

module Endpoint : sig
  type t = endpoint with sexp
  type mapping = (t * t) with sexp
  include Inds_types.KEY with type t := t
end = struct
  open Sexplib.Std
  type t = (Ipaddr.t * int) with sexp
  type mapping = (t * t) with sexp

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)
  let of_string str =
    try Some (t_of_sexp (Sexplib.Sexp.of_string str))
    with Sexplib.Pre_sexp.Of_sexp_error _ -> None

  let compare (ip1, port1) (ip2, port2) =
    match compare port1 port2 with
    | 0 -> compare ip1 ip2
    | n -> n

  let to_json entry = Ezjsonm.of_sexp (sexp_of_t entry)
  let of_json json = t_of_sexp (Ezjsonm.to_sexp json)

end

module Entry : sig
  type entry = (endpoint * endpoint) with sexp
  type t = | Confirmed of int * entry with sexp
  type result = [ `Ok of entry | `Timeout ]
  include Inds_types.ENTRY
    with type entry := entry
     and type t := t
     and type result := result
  val of_string : string -> t option
  val to_string : t -> string
  val size_of : t -> int
  val equal : t -> t -> bool
end = struct
  open Sexplib.Std
  type entry = (Endpoint.t * Endpoint.t) with sexp
  type t = | Confirmed of int * entry with sexp
  type result = [ `Ok of entry | `Timeout ]
                (* t and result feel wrong here *)
  let make_confirmed time entry = Confirmed (time, entry)

  let to_json t = Ezjsonm.of_sexp (sexp_of_t t)

  let of_json json = t_of_sexp (Ezjsonm.to_sexp json)

  let compare (Confirmed (t1, e1)) (Confirmed (t2, e2)) =
    match compare e1 e2 with
    | 0 -> compare t1 t2
    | n -> n

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)

  let of_string str =
    try Some (t_of_sexp (Sexplib.Sexp.of_string str))
    with Sexplib.Pre_sexp.Of_sexp_error _ -> None

  let size_of t = String.length (to_string t)

  let equal x y = (compare x y) = 0

end

module Key : sig
  type protocol = | Udp | Tcp with sexp
  type t = (protocol * Endpoint.t * Endpoint.t) with sexp
  include Inds_types.KEY with type t := t
end = struct
  open Sexplib.Std
  type protocol = | Udp | Tcp with sexp
  type t = (protocol * Endpoint.t * Endpoint.t) with sexp

  let compare (proto_l, src_l, dst_l) (proto_r, src_r, dst_r) =
    match compare proto_l proto_r with
    | 0 -> (
        match Endpoint.compare src_l src_r with
        | 0 -> Endpoint.compare dst_l dst_r
        | n -> n
      )
    | n -> n

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)
  let of_string str =
    try Some (t_of_sexp (Sexplib.Sexp.of_string str))
    with Sexplib.Pre_sexp.Of_sexp_error _ -> None

  let to_json t = Ezjsonm.of_sexp (sexp_of_t t)
  let of_json json = t_of_sexp (Ezjsonm.to_sexp json)

  let size_of t = String.length (to_string t)
end
