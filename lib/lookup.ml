(* TODO: what are the actual data types on these?  no explicit
types in tcpip/lib/ipv4.ml, just matches on the number
straight from the struct, so we'll do that too although we
   should instead restrict to tcp or udp *) 

(* TODO: types should actually be more complex and allow for entries mapping
  networks and port ranges (with internal logic disallowing many:many mappings)
*)
type protocol = int
type port = int (* TODO: should probably formalize that this is uint16 *)
type t = (protocol * (Ipaddr.t * port) * (Ipaddr.t * port), (Ipaddr.t * port)) Hashtbl.t

(* 
let dump_table (table : table) =
  let print_pair (addr, port) =
    Printf.sprintf "addr %s , port %d (%x) " (Ipaddr.to_string addr) port port
  in
  Hashtbl.iter (
    fun (proto, left, right) answer -> 
      Printf.printf "proto %d (%x): %s, %s -> %s\n" 
        proto proto (print_pair left) (print_pair right) (print_pair answer)
  ) table
*)

(* this is really only useful for debugging *)
let length table = Hashtbl.length table

let lookup table proto left right =
  match Hashtbl.mem table (proto, left, right) with
  | false -> None
  | true -> Some (Hashtbl.find table (proto, left, right))

(* cases that should result in a valid mapping: 
   neither side is already mapped
   both sides are already mapped to each other (currently this would be a noop,
but there may in the future be more state associated with these entries that
  then should be updated) *)
let insert table proto left right translate =
  let open Hashtbl in
  let internal_lookup = (proto, left, right) in
  let external_lookup = (proto, right, translate) in
  (* TODO: this is subject to race conditions *)
  (* needs Lwt.join *)
  match (mem table internal_lookup, mem table external_lookup) with
  | false, false ->
    add table internal_lookup translate;
    add table external_lookup left;
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
  
