type 'a layer = Cstruct.t
type protocol = int
type ethernet
type ip
type transport
type payload

open Ipaddr
open Nat_shims

(* TODO: it's not clear where this function should be, but it probably shouldn't
   be here in the long run. *)
let addresses_of_ip ip_packet =
  let hlen_version = Wire_structs.Ipv4_wire.get_ipv4_hlen_version ip_packet in
  let ip_type = ((hlen_version land 0xf0) lsr 4) in
  match ip_type with
  | 4 -> (* ipv4 *)
    (Ipaddr.V4 (Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_src ip_packet)),
     Ipaddr.V4 (Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_dst ip_packet)))
  | 6 -> (* ipv6 *)
    (Ipaddr.V6 (V6.of_cstruct_exn (Wire_structs.Ipv6_wire.get_ipv6_src ip_packet)),
     Ipaddr.V6 (V6.of_cstruct_exn (Wire_structs.Ipv6_wire.get_ipv6_dst ip_packet)))
  | _ -> failwith "invalid ip type in packet"

let retrieve_ports tx_layer =
  (* Cstruct.uint16, Cstruct.uint16 *)
  if (Cstruct.len tx_layer < (Wire_structs.sizeof_udp)) then None else Some
      ((Wire_structs.get_udp_source_port tx_layer : int),
       (Wire_structs.get_udp_dest_port tx_layer : int))

let proto_of_ip ip_layer =
  let hlen_version = Wire_structs.Ipv4_wire.get_ipv4_hlen_version ip_layer in
  match ((hlen_version land 0xf0) lsr 4) with
  | 4 -> Wire_structs.Ipv4_wire.get_ipv4_proto ip_layer
  | 6 -> Wire_structs.Ipv6_wire.get_ipv6_nhdr ip_layer
  | _ -> failwith "invalid ip type in packet"

let ip_header_length hlen_version =
  match ((hlen_version land 0xf0) lsr 4) with
  | 4 -> (* length (in words, not bytes) is in the other half of hlen_version *)
    Some ((hlen_version land 0x0f) * 4)
  | 6 -> (* ipv6 is a constant length *)
    Some Wire_structs.Ipv6_wire.sizeof_ipv6
  | n -> None

let transport_and_above_of_ip ip =
  let long_enough = function
    | 6 -> Some Wire_structs.Tcp_wire.sizeof_tcp
    | 17 -> Some Wire_structs.sizeof_udp
    | _ -> None
  in
  let hlen_version = Wire_structs.Ipv4_wire.get_ipv4_hlen_version ip in
  match ip_header_length hlen_version with
  | None -> None
  | Some n ->
    match long_enough (proto_of_ip ip) with
    | None -> None
    | Some minimum_tx_header ->
      if ((Cstruct.len ip) < (n + minimum_tx_header)) then
        None
      else
        Some (Cstruct.shift ip n)

let payload_of_transport proto tx =
  match proto with
  | 6 ->
    if (Cstruct.len tx < Wire_structs.Tcp_wire.sizeof_tcp) then None else begin
      let word_offset = (Wire_structs.Tcp_wire.get_tcp_dataoff tx) lsr 4 in
      let byte_offset = word_offset * 4 in
      if (Cstruct.len tx < byte_offset) then None
      else Some (Cstruct.shift tx byte_offset)
    end
  | 17 ->
    (* UDP isn't variable-length, so things are much simpler *)
    if (Cstruct.len tx < Wire_structs.sizeof_udp) then None
    else Some (Cstruct.shift tx (Wire_structs.sizeof_udp))
  | _ -> None

let ports_of_transport tx_layer =
  ((Wire_structs.get_udp_source_port tx_layer : int),
   (Wire_structs.get_udp_dest_port tx_layer : int))

let ethip_headers i =
  match ip_header_length (Wire_structs.Ipv4_wire.get_ipv4_hlen_version i) with
  | Some ip_len when Cstruct.len i >= ip_len ->
    Some (Cstruct.sub i 0 ip_len)
  | None | Some _ -> None

let layers ip =
  MProf.Trace.label "Nat_decompose.layers";
  match transport_and_above_of_ip ip with
  | None -> None
  | Some tx ->
    let proto = proto_of_ip ip in
    match payload_of_transport proto tx with
    | None -> None
    | Some payload -> Some (ip, tx, payload)

let rewrite_ip is_ipv6 (ip_layer : Cstruct.t) i =
  (* TODO: this is not the right set of parameters for a function that might
       have to do 6-to-4 translation *)
  (* also, TODO all of the 6-to-4/4-to-6 thoughts and code.  nbd. *)
  match (is_ipv6, i) with
  | false, (V4 new_src, V4 new_dst) ->
    Wire_structs.Ipv4_wire.set_ipv4_src ip_layer (Ipaddr.V4.to_int32 new_src);
    Wire_structs.Ipv4_wire.set_ipv4_dst ip_layer (Ipaddr.V4.to_int32 new_dst)
  | _, _ -> raise (Failure "ipv4-ipv4 is the only implemented case")

let rewrite_port (txlayer : Cstruct.t) (sport, dport) =
  Wire_structs.set_udp_source_port txlayer sport;
  Wire_structs.set_udp_dest_port txlayer dport

let recalculate_ip_checksum ip_layer tx_layer =
  let size = ((Cstruct.len ip_layer) - (Cstruct.len tx_layer)) in
  Wire_structs.Ipv4_wire.set_ipv4_csum ip_layer 0;
    let just_ipv4 = Cstruct.sub ip_layer 0 size in
    let new_csum = Tcpip_checksum.ones_complement just_ipv4 in
    Wire_structs.Ipv4_wire.set_ipv4_csum ip_layer new_csum

let finalize_packet (ip_layer, transport_layer, payload) =
  match ethip_headers (ip_layer) with
  | None -> raise (Invalid_argument
                     "Could not recalculate transport-layer checksum after NAT rewrite")
  | Some just_headers ->
    let fix_checksum set_checksum ip_layer higherlevel_data =
      (* reset checksum to 0 for recalculation *)
      set_checksum higherlevel_data 0;
      let actual_checksum = Wire_structs.Ipv4_wire.checksum ip_layer (higherlevel_data :: []) in
      set_checksum higherlevel_data actual_checksum
    in
    let () = match proto_of_ip ip_layer with
      | 17 -> fix_checksum Wire_structs.set_udp_checksum ip_layer transport_layer
      | 6 ->
        fix_checksum Wire_structs.Tcp_wire.set_tcp_checksum ip_layer transport_layer
      | _ -> ()
    in
    (just_headers, transport_layer)

let set_smac ethernet mac =
  Wire_structs.set_ethernet_src (Macaddr.to_bytes mac) 0 ethernet;
  ethernet

let decrement_ttl ip_layer =
  Wire_structs.Ipv4_wire.set_ipv4_ttl ip_layer
    ((Wire_structs.Ipv4_wire.get_ipv4_ttl ip_layer) - 1)

let compare a b = Cstruct.compare a b
