(* TODO: what are the actual data types on these?  no explicit
types in tcpip/lib/ipv4.ml, just matches on the number
straight from the struct, so we'll do that too although we
should instead restrict to tcp or udp *) 
type protocol = int
type port = int (* TODO: should probably formalize that this is uint16 *)
type table = ((Ipaddr.t * port * protocol), (Ipaddr.t * port)) Hashtbl.t

type t =
  {
     protocol : protocol;
     left_ip : Ipaddr.t;
     right_ip : Ipaddr.t;
     left_port : port; 
     right_port : port;
  }

let lookup table proto addr port = try Some (Hashtbl.find table (addr, port,
                                                                 proto))
  with Not_found -> None

let insert table proto (left_ip, left_port) (right_ip, right_port) =
  (* TODO: this is subject to race conditions *)
  Hashtbl.replace table (left_ip, left_port, proto) (right_ip, right_port);
  Hashtbl.replace table (right_ip, right_port, proto) (left_ip, left_port);
  table

let delete table proto (left_ip, left_port) (right_ip, right_port) =
  (* TODO: this is subject to race conditions *)
  Hashtbl.remove table (left_ip, left_port, proto);
  Hashtbl.remove table (right_ip, right_port, proto);
  table

(* TODO: if we do continue with this structure, this number should almost
  certainly be bigger *)
let empty () = Hashtbl.create 200
  
let t_of_strings (left_ip, left_port) (right_ip, right_port) protocol =
  let make_ip str =
    Ipaddr.of_string_exn str
  in
  { 
    left_ip = make_ip left_ip;
    right_ip = make_ip right_ip;
    left_port;
    right_port;
    protocol
  }
