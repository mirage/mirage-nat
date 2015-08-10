module Endpoint = struct
  open Sexplib.Std
  type t = (Ipaddr.t * int) with sexp

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)
  let of_string str =
    try Some (t_of_sexp (Sexplib.Sexp.of_string str))
    with Sexplib.Pre_sexp.Of_sexp_error _ -> None

  let compare (ip1, port1) (ip2, port2) =
    match compare port1 port2 with
    | 0 -> compare ip1 ip2
    | n -> n

  let to_json entry = Ezjsonm.of_sexp (sexp_of_t entry)

  let of_json json =
    try Some (t_of_sexp (Ezjsonm.to_sexp json))
    with Sexplib.Pre_sexp.Of_sexp_error (_, _) -> None

end

module Entry : sig
  type entry = (Endpoint.t * Endpoint.t) with sexp
  type t = | Confirmed of int * entry with sexp
  type result = [ `Ok of entry | `Timeout ]
  include Inds_types.ENTRY
    with type entry := entry
     and type t := t
     and type result := result
  val of_string : string -> t option
end = struct
  open Sexplib.Std
  type entry = (Endpoint.t * Endpoint.t) with sexp
  type t = | Confirmed of int * entry with sexp
  type result = [ `Ok of entry | `Timeout ]
                (* t and result feel wrong here *)
  let make_confirmed time entry = Confirmed (time, entry)

  let to_json t = Ezjsonm.of_sexp (sexp_of_t t)

  let of_json json =
    try Some (t_of_sexp (Ezjsonm.to_sexp json))
    with Ezjsonm.Parse_error _ -> None

  let compare (Confirmed (t1, e1)) (Confirmed (t2, e2)) =
    match compare e1 e2 with
    | 0 -> compare t1 t2
    | n -> n

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)

  let of_string str =
    try Some (t_of_sexp (Sexplib.Sexp.of_string str))
    with Sexplib.Pre_sexp.Of_sexp_error _ -> None

end

module Key : sig
  type t = (Endpoint.t * Endpoint.t) with sexp
  include Inds_types.KEY with type t := t
end = struct
  open Sexplib.Std
  type t = (Endpoint.t * Endpoint.t) with sexp

  let compare (src_l, dst_l) (src_r, dst_r) =
    match Endpoint.compare src_l src_r with
    | 0 -> Endpoint.compare dst_l dst_r
    | n -> n

  let to_string t = Sexplib.Sexp.to_string (sexp_of_t t)
  let of_string str =
    try Some (t_of_sexp (Sexplib.Sexp.of_string str))
    with Sexplib.Pre_sexp.Of_sexp_error _ -> None
end
