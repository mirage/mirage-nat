type transport = | Tcp of (Tcp.Tcp_packet.t * Cstruct.t)
                 | Udp of (Udp_packet.t * Cstruct.t)
                 | Icmp of (Icmpv4_packet.t * Cstruct.t)

type network = | Ipv4 of (Ipv4_packet.t * Cstruct.t)
               | Ipv6 of (Cstruct.t * Cstruct.t)
               | Arp of Arpv4_packet.t

type decomposed =
  { ethernet : Ethif_packet.t * Cstruct.t;
    network : network;
    transport : transport option;
  }

let (>>=) = Rresult.(>>=)

let decompose buf =
  let open Rresult in
  let get_transport proto b =
    match Ipv4_packet.Unmarshal.int_to_protocol proto with
    | None -> Result.Ok None
    | Some `ICMP ->
      Icmpv4_packet.Unmarshal.of_cstruct b >>= fun icmp -> Result.Ok (Some (Icmp icmp))
    | Some `TCP ->
      Tcp.Tcp_packet.Unmarshal.of_cstruct b >>= fun tcp -> Result.Ok (Some (Tcp tcp))
    | Some `UDP ->
      Udp_packet.Unmarshal.of_cstruct b >>= fun udp -> Result.Ok (Some (Udp udp))
  in
  Ethif_packet.Unmarshal.of_cstruct buf >>= fun (e, e_payload) ->
  match e.ethertype with
  | Ethif_wire.IPv6 ->
    let header = Cstruct.sub e_payload 0 Ipv6_wire.sizeof_ipv6 in
    let payload = Cstruct.shift e_payload Ipv6_wire.sizeof_ipv6 in
    get_transport (Ipv6_wire.get_ipv6_nhdr header) payload >>= fun transport ->
    Ok { ethernet = (e, e_payload) ; network = Ipv6 (header, payload);
         transport}
  | Ethif_wire.IPv4 ->
    Ipv4_packet.Unmarshal.of_cstruct e_payload >>= fun (ip, ip_payload) ->
    get_transport ip.proto ip_payload >>= fun transport ->
    Ok { ethernet = (e, e_payload); network = Ipv4 (ip, ip_payload); transport }
  | Ethif_wire.ARP ->
    match Arpv4_packet.Unmarshal.of_cstruct e_payload with
    | Result.Error e -> Result.Error (Arpv4_packet.Unmarshal.string_of_error e)
    | Result.Ok a ->
      Ok { ethernet = (e, e_payload); network = (Arp a); transport = None; }

let ports = function
  | None | Some (Icmp _) -> None
  | Some (Tcp (header, _) as transport) ->
    let open Tcp.Tcp_packet in
    Some (Mirage_nat.Tcp, transport, header.src_port, header.dst_port)
  | Some (Udp (header, _) as transport) ->
    let open Udp_packet in
    Some (Mirage_nat.Udp, transport, header.src_port, header.dst_port)

let rewrite_packet packet ~src:(src, src_port) ~dst:(dst,dst_port) =
  let `IPv4 (ip_header, transport) = packet in
  match Ipv4_packet.(ip_header.ttl) with
  | 0 -> Error "TTL exceeded"
  | n ->
    let ttl = n - 1 in
    let new_ip_header = { ip_header with src; dst; ttl} in
    match transport with
    | `UDP (udp_header, udp_payload) ->
      let new_transport_header = { udp_header with Udp_packet.src_port; dst_port } in
      Logs.debug (fun f -> f "UDP header rewritten to: %a" Udp_packet.pp new_transport_header);
      Ok (`IPv4 (new_ip_header, `UDP (new_transport_header, udp_payload)))
    | `TCP (tcp_header, tcp_payload) ->
      let new_transport_header = { tcp_header with Tcp.Tcp_packet.src_port; dst_port } in
      Logs.debug (fun f -> f "TCP header rewritten to: %a" Tcp.Tcp_packet.pp new_transport_header);
      Ok (`IPv4 (new_ip_header, `TCP (new_transport_header, tcp_payload)))
