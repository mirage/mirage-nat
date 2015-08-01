(* TODO: what are the data types on protocol numbers?  no explicit
types in tcpip/lib/ipv4.ml, just matches on the number
straight from the struct, so we'll do that too although we
   should instead restrict to tcp or udp *)

(* TODO: types should be more complex and allow for entries mapping
  networks and port ranges (with internal logic disallowing many:many mappings)
*)
type protocol = int
type port = int (* TODO: should probably formalize that this is uint16 *)
type t = (protocol * (Ipaddr.t * port) * (Ipaddr.t * port),
          ((Ipaddr.t * port) * (Ipaddr.t * port))) Hashtbl.t
type mode =
  | Redirect
  | Nat

let string_of_t (table : t) =
  let print_pair (addr, port) =
    Printf.sprintf "addr %s , port %d (%x) " (Ipaddr.to_string addr) port port
  in
  Hashtbl.fold (
    fun (proto, left, right) answer str ->
      Printf.sprintf "%s proto %d (%x): %s, %s -> %s, %s\n" str
        proto proto (print_pair left) (print_pair right)
        (print_pair (fst answer)) (print_pair (snd answer))
  ) table ""

let lookup table proto left right =
  match Hashtbl.mem table (proto, left, right) with
  | false -> None
  | true -> Some (Hashtbl.find table (proto, left, right))

(* cases that should result in a valid mapping:
   neither side is already mapped
   both sides are already mapped to each other (currently this would be a noop,
but there may in the future be more state associated with these entries that
  then should be updated) *)
let insert ?(mode=Nat) table proto left right translate_left translate_right =
  let open Hashtbl in
  let mappings = function
    | Nat ->
      let internal_lookup = (proto, left, right) in
      let external_lookup = (proto, right, translate_left) in
      let internal_mapping = (translate_left, right) in
      let external_mapping = (right, left) in
      (internal_lookup, external_lookup, internal_mapping, external_mapping)
    | Redirect ->
      let internal_lookup = (proto, left, translate_left) in
      let external_lookup = (proto, right, translate_right) in
      let internal_mapping = (translate_right, right) in
      let external_mapping = (translate_left, left) in
      (internal_lookup, external_lookup, internal_mapping, external_mapping)
  in
  let (internal_lookup, external_lookup, internal_mapping, external_mapping) =
    mappings mode
  in
  (* TODO: this is subject to race conditions *)
  match (mem table internal_lookup, mem table external_lookup) with
  | false, false ->
    add table internal_lookup internal_mapping;
    add table external_lookup external_mapping;
    Some table
  | _, _ -> None (* there's already a table entry *)

let delete table proto (left_ip, left_port) (right_ip, right_port)
    (translate_ip, translate_port) (translate_right_ip, translate_right_port) =
  (* TODO: this is probably not right for redirects *)
  let internal_lookup = (proto, (left_ip, left_port), (right_ip, right_port)) in
  let external_lookup = (proto, (right_ip, right_port), (translate_ip,
                                                          translate_port)) in
  (* TODO: this is subject to race conditions *)
  (* needs Lwt.join *)
  (* TODO: under what circumstances does this return None? *)
  Hashtbl.remove table internal_lookup;
  Hashtbl.remove table external_lookup;
  Some table

(* TODO: if we do continue with this structure, this number should almost
  certainly be bigger *)
let empty () = Hashtbl.create 200

