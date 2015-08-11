open Ipaddr
open Nat_lookup
open Nat_shims (* V4 and V6 definitions *)

type 'a layer = 'a Nat_decompose.layer
type ethernet = Nat_decompose.ethernet
type ip = Nat_decompose.ip
type transport = Nat_decompose.transport

type direction = Source | Destination

let rewrite_ip is_ipv6 (ip_layer : Cstruct.t) direction i =
  (* TODO: this is not the right set of parameters for a function that might
       have to do 6-to-4 translation *)
  (* also, TODO all of the 6-to-4/4-to-6 thoughts and code.  nbd. *)
  match (is_ipv6, direction, i) with
  | false, _, (V4 new_src, V4 new_dst) ->
    Wire_structs.Ipv4_wire.set_ipv4_src ip_layer (Ipaddr.V4.to_int32 new_src);
    Wire_structs.Ipv4_wire.set_ipv4_dst ip_layer (Ipaddr.V4.to_int32 new_dst)
  | _, _, _ -> raise (Failure "ipv4-ipv4 is the only implemented case")

let rewrite_port (txlayer : Cstruct.t) direction (sport, dport) =
  Wire_structs.set_udp_source_port txlayer sport;
  Wire_structs.set_udp_dest_port txlayer dport

let recalculate_transport_checksum csum_fn (ethernet, ip_layer, transport_layer) =
  match Nat_decompose.ethip_headers (ethernet, ip_layer) with
  | None -> raise (Invalid_argument 
                     "Could not recalculate transport-layer checksum after NAT rewrite")
  | Some just_headers ->
    let fix_checksum set_checksum ip_layer higherlevel_data =
      (* reset checksum to 0 for recalculation *)
      set_checksum higherlevel_data 0;
      let actual_checksum = csum_fn just_headers (higherlevel_data :: []) in
      set_checksum higherlevel_data actual_checksum
    in
    let () = match Nat_decompose.proto_of_ip ip_layer with
      | 17 -> fix_checksum Wire_structs.set_udp_checksum ip_layer transport_layer 
      | 6 ->
        fix_checksum Wire_structs.Tcp_wire.set_tcp_checksum ip_layer transport_layer
      | _ -> ()
    in
    (just_headers, transport_layer)

let set_smac ethernet mac =
  Wire_structs.set_ethernet_src (Macaddr.to_bytes mac) 0 ethernet;
  ethernet

module Make(N : Nat_lookup.S) = struct
  type insert_result =
    | Ok of N.t
    | Overlap
    | Unparseable

  let (>>=) = Lwt.bind

  let protofy num = match num with
    | 6 -> Some Tcp
    | 17 -> Some Udp
    | _ -> None

  let translate table direction frame =
    (* note that ethif.input doesn't have the same register-listeners-then-input
       format that tcp/udp do, so we could use it for the outer layer of parsing *)
    let decrement_ttl ip_layer =
      Wire_structs.Ipv4_wire.set_ipv4_ttl ip_layer
        ((Wire_structs.Ipv4_wire.get_ipv4_ttl ip_layer) - 1)
    in
    (* TODO: this is not correct for IPv6 *)
    (* TODO: it's not clear to me whether we need to do this, since most users
       will be sending packets via IP.write, which itself calculates and inserts
       the proper checksum before sending the packet. *)
    let recalculate_ip_checksum ip_layer size =
      Wire_structs.Ipv4_wire.set_ipv4_csum ip_layer 0;
      let just_ipv4 = Cstruct.sub ip_layer 0 size in
      let new_csum = Tcpip_checksum.ones_complement just_ipv4 in
      Wire_structs.Ipv4_wire.set_ipv4_csum ip_layer new_csum
    in
    match Nat_decompose.layers frame with
    | None -> Lwt.return None (* un-NATtable packet; drop it like it's hot *)
    | Some (frame, ip_packet, higherproto_packet, _payload) ->
      match (Nat_decompose.addresses_of_ip ip_packet) with
      | (V4 src, V6 dst) -> Lwt.return None (* impossible! *)
      | (V6 src, V4 dst) -> Lwt.return None (* impossible! *)
      | (V6 src, V6 dst) -> Lwt.return None (* TODO, obviously *)
      | (V4 src, V4 dst) ->
        match protofy (Nat_decompose.proto_of_ip ip_packet) with
        | None -> Lwt.return None (* TODO: don't just drop all non-udp, non-tcp packets *)
        | Some proto ->
          let (sport, dport) = Nat_decompose.ports_of_transport higherproto_packet in
          (* got everything; do the lookup *)
          N.lookup table proto ((V4 src), sport) ((V4 dst), dport) >>= function
          | None -> Lwt.return None (* don't autocreate new entries *)
          | Some ((V4 new_src, new_sport), (V4 new_dst, new_dport)) ->
            (* TODO: we should probably refuse to pass TTL = 0 and instead send an
               ICMP message back to the sender *)
            rewrite_ip false ip_packet direction (V4 new_src, V4 new_dst);
            rewrite_port higherproto_packet direction (new_sport, new_dport);
            decrement_ttl ip_packet;
            recalculate_ip_checksum ip_packet  
              ((Cstruct.len ip_packet) - (Cstruct.len higherproto_packet));
            Lwt.return (Some frame)

          (* TODO: 4-to-6 logic *)
          | Some ((V6 new_src, new_sport), (V6 new_dst, new_dport)) ->
            Lwt.return None
          | Some ((V6 _, _), (V4 _, _)) ->
            raise (Invalid_argument "Impossible transformation in NAT
                                         table (src ipv6, dst ipv4)")
          | Some ((V4 _, _), (V6 _, _)) ->
            raise (Invalid_argument "Impossible transformation in NAT
                                         table (src ipv4, dst ipv6)")

  let make_entry mode table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    (* decompose this frame; if we can't, bail out now *)
    match Nat_decompose.layers frame with
    | None -> Lwt.return Unparseable
    | Some (frame, ip_layer, tx_layer, _payload) ->
      let proto = protofy (Nat_decompose.proto_of_ip ip_layer) in
      let check_scope ip =
        match Ipaddr.scope ip with
        | Global | Organization -> true
        | _ -> false
      in
      let (frame_src_ip, frame_dst_ip) = Nat_decompose.addresses_of_ip ip_layer in
      let (frame_sport, frame_dport) = Nat_decompose.ports_of_transport tx_layer in
      (* only Organization and Global scope IPs and UDP/TCP tx layer get routed *)
      match proto, check_scope frame_src_ip, check_scope frame_dst_ip with
      | Some proto, true, true -> (
          let open Nat_translations in
          let entries = match mode with
            | Nat ->
              map_nat
                ~left:(frame_src_ip, frame_sport)
                ~right:(frame_dst_ip, frame_dport)
                ~translate_left:(other_xl_ip, other_xl_port)
            | Redirect ->
              map_redirect
                ~left:(frame_src_ip, frame_sport)
                ~right:(final_destination_ip, final_destination_port)
                ~translate_left:(frame_dst_ip, frame_dport)
                ~translate_right:(other_xl_ip, other_xl_port)
          in
          let expiration_window =
            match proto with
            | Udp -> 60 (* UDP gets 60 seconds *)
            | Tcp -> 60*60*24 (* TCP gets a day *)
          in
          N.insert table expiration_window proto
            ~internal_lookup:entries.internal_lookup
            ~external_lookup:entries.external_lookup
            ~internal_mapping:entries.internal_mapping
            ~external_mapping:entries.external_mapping
          >>= function
          | Some t -> Lwt.return (Ok t)
          | None -> Lwt.return Overlap
        )
      | _, _, _ -> Lwt.return Unparseable

  (* the frame is addressed to one of our IPs.  We should rewrite the source with
     the IP of our other interface, along with a randomized port. *)
  (* We need to be told the real destination IP and port (possibly we can assume
     the same as the port the frame was addressed to). *)
  let make_redirect_entry table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    make_entry (Redirect : Nat_lookup.mode) table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port)

  let make_nat_entry table frame xl_ip xl_port =
    make_entry (Nat : Nat_lookup.mode) table frame (xl_ip, xl_port) (xl_ip, xl_port)

end
