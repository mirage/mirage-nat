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

let rewrite_packet ~ethernet:(eth_header, eth_payload)
                   ~network:(ip_header, ip_payload)
                   ~transport ~src:(src, src_port) ~dst:(dst,dst_port) =
  let check_ttl ip_header =
    match Ipv4_packet.(ip_header.ttl) with
    | 0 -> Result.Error "TTL exceeded"
    | n -> Result.Ok (n - 1)
  in
     check_ttl ip_header >>= fun ttl ->
     let new_ip_header = { ip_header with src; dst; ttl} in
     match transport with
     | Icmp _ -> Result.Error "I don't rewrite ICMP packets"
     | Udp (udp_header, udp_payload) ->
       let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP (Cstruct.len udp_payload + Udp_wire.sizeof_udp) in
       let new_transport_header = { udp_header with src_port; dst_port } in
       (* mutate the transport layer first,
        * so we calculate the correct checksum when we
        * mutate the network layer *)
       Udp_packet.Marshal.into_cstruct
         ~pseudoheader new_transport_header
         ~payload:udp_payload ip_payload >>= fun () ->
       Logs.debug (fun f -> f "UDP header rewritten.  ethernet payload now looks like this: %a" Cstruct.hexdump_pp eth_payload);
       Ipv4_packet.Marshal.into_cstruct ~payload:ip_payload new_ip_header eth_payload;
       Logs.debug (fun f -> f "IP header rewritten.  ethernet payload now looks like this: %a" Cstruct.hexdump_pp eth_payload);
       Result.Ok ()
     | Tcp (tcp_header, tcp_payload) ->
       (* TODO: unfortunately, in order to correctly figure out the pseudoheader (and thus the TCP checksum),
        * we need to know the length field of the IPv4 header.  That means we need to know the *overall* length,
        * which means we need to know how many bytes are required to marshal the TCP options. *)
       let options_buf = Cstruct.create 60 in
       let options_length = Tcp.Options.marshal options_buf tcp_header.options in
       let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`TCP (Tcp.Tcp_wire.sizeof_tcp + options_length + Cstruct.len tcp_payload) in
       let new_transport_header = { tcp_header with src_port; dst_port } in
       Tcp.Tcp_packet.Marshal.into_cstruct
         ~pseudoheader new_transport_header
         ~payload:tcp_payload ip_payload >>= fun bytes ->
       Logs.debug (fun f -> f "TCP header rewritten (%d bytes).  ethernet payload now looks like this: %a" bytes Cstruct.hexdump_pp eth_payload);
       Ipv4_packet.Marshal.into_cstruct ~payload:ip_payload new_ip_header eth_payload;
       Logs.debug (fun f -> f "rewrote a packet.  ethernet payload now looks like this: %a" Cstruct.hexdump_pp eth_payload);
       Result.Ok ()
