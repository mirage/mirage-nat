type 'a layer = Cstruct.t
type protocol = int
type ethernet
type ip
type transport
type payload

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

let ip_and_above_of_frame frame =
  let minimal_size = function
    | 0x0800 -> Wire_structs.Ipv4_wire.sizeof_ipv4 + Wire_structs.sizeof_ethernet
    | 0x86dd -> Wire_structs.Ipv6_wire.sizeof_ipv6 +
                Wire_structs.sizeof_ethernet
    | _ -> raise (Invalid_argument "minimal_size called with unknown ethertype")
  in
  let ethertype = (Wire_structs.get_ethernet_ethertype frame) in
  match ethertype with
  | 0x0800 | 0x86dd ->
    if (Cstruct.len frame) < (minimal_size ethertype) then None
    else Some (Cstruct.shift frame Wire_structs.sizeof_ethernet)
  | _ -> None

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

let ethip_headers (e, i) =
  let ethersize = Wire_structs.sizeof_ethernet in
  match ip_header_length (Wire_structs.Ipv4_wire.get_ipv4_hlen_version i) with
  | Some ip_len when Cstruct.len e >= (ethersize + ip_len) ->
    Some (Cstruct.sub e 0 (ethersize + ip_len))
  | None | Some _ -> None

let layers frame =
  MProf.Trace.label "Nat_decompose.layers";
  match ip_and_above_of_frame frame with
  | None -> None
  | Some ip ->
    match transport_and_above_of_ip ip with
    | None -> None
    | Some tx ->
      let proto = proto_of_ip ip in
      match payload_of_transport proto tx with
      | None -> None
      | Some payload -> Some (frame, ip, tx, payload)
