(* TODO: what are the actual data types on these?  no explicit
types in tcpip/lib/ipv4.ml, just matches on the number
straight from the struct, so we'll do that too although we
should instead restrict to tcp or udp *) 
type protocol = int
type port = int (* TODO: should probably formalize that this is uint16 *)
type table = (protocol * (Ipaddr.t * port) * (Ipaddr.t * port), (Ipaddr.t * port)) Hashtbl.t

let lookup table proto left right =
  match Hashtbl.mem table (proto, left, right) with
  | false -> None
  | true -> Some (Hashtbl.find table (proto, left, right))

(* cases that should result in a valid mapping: 
   neither side is already mapped
   both sides are already mapped to each other (currently this would be a noop,
but there may in the future be more state associated with these entries that
  then should be updated) *)
let insert table proto (left_ip, left_port) (right_ip, right_port)
    (translate_ip, translate_port) =
  let open Hashtbl in
  let internal_lookup = (proto, (left_ip, left_port), (right_ip, right_port)) in
  let external_lookup = (proto, (right_ip, right_port), (translate_ip,
                                                          translate_port)) in
  (* TODO: this is subject to race conditions *)
  (* needs Lwt.join *)
  match (mem table internal_lookup, mem table external_lookup) with
  | false, false ->
    add table internal_lookup (translate_ip, translate_port);
    add table external_lookup (left_ip, left_port);
    Some table
  | _, _ -> None (* there's already a table entry *)

let delete table proto (left_ip, left_port) (right_ip, right_port)
    (translate_ip, translate_port) =
  let internal_lookup = (proto, (left_ip, left_port), (right_ip, right_port)) in
  let external_lookup = (proto, (right_ip, right_port), (translate_ip,
                                                          translate_port)) in
  (* TODO: this is subject to race conditions *)
  (* needs Lwt.join *)
  Hashtbl.remove table internal_lookup;
  Hashtbl.remove table external_lookup;
  table

(* TODO: if we do continue with this structure, this number should almost
  certainly be bigger *)
let empty () = Hashtbl.create 200
  
