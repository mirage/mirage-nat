(* TODO: what are the data types on protocol numbers?  no explicit
types in tcpip/lib/ipv4.ml, just matches on the number
straight from the struct, so we'll do that too although we
   should instead restrict to tcp or udp *)

(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]
*)
type protocol = int
type port = int (* TODO: should probably formalize that this is uint16 *)
type endpoint = (Ipaddr.t * port)
type mapping = (endpoint * endpoint)
type t = (protocol * endpoint * endpoint,
          (endpoint * endpoint)) Hashtbl.t

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

let lookup table proto ~source ~destination =
  match Hashtbl.mem table (proto, source, destination) with
  | false -> None
  | true -> Some (Hashtbl.find table (proto, source, destination))


(* cases that should result in a valid mapping:
   neither side is already mapped
   both sides are already mapped to each other (currently this would be a noop,
   but there may in the future be more state associated with these entries that
   then should be updated) *)
let insert table proto
    ~internal_lookup ~external_lookup ~internal_mapping ~external_mapping =
  let protofy proto (src, dst) = (proto, src, dst) in
  let check proto (src, dst) = Hashtbl.mem table (protofy proto (src, dst)) in
  match (check proto internal_lookup, check proto external_lookup) with
  | false, false ->
    (* probably best to have a branch-and-merge here *)
    Hashtbl.add table (protofy proto internal_lookup) internal_mapping;
    Hashtbl.add table (protofy proto external_lookup) external_mapping;
    Some table
  | _, _ -> None (* there's already a table entry *)

let delete table proto (left_ip, left_port) (right_ip, right_port)
    (translate_ip, translate_port) (translate_right_ip, translate_right_port) =
  (* TODO: this is probably not right for redirects *)
  let internal_lookup = (proto, (left_ip, left_port), (right_ip, right_port)) in
  let external_lookup = (proto, (right_ip, right_port), (translate_ip,
                                                          translate_port)) in
  (* TODO: under what circumstances does this return None? *)
  (* branch and merge here *)
  Hashtbl.remove table internal_lookup;
  Hashtbl.remove table external_lookup;
  Some table

let empty () = Hashtbl.create 200

