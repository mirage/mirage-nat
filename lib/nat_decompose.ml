let rewrite_icmp ~src_port icmp =
  match icmp.Icmpv4_packet.subheader with
  | Icmpv4_packet.Id_and_seq (_, seq) ->
    Ok {icmp with Icmpv4_packet.subheader = Icmpv4_packet.Id_and_seq (src_port, seq)}
  | _ ->
    Error "Unsupported ICMP packet"

let rewrite_packet packet ~src:(src, src_port) ~dst:(dst,dst_port) =
  let `IPv4 (ip_header, transport) = packet in
  match Ipv4_packet.(ip_header.ttl) with
  | 0 -> Error "TTL exceeded"
  | n ->
    let ttl = n - 1 in
    let new_ip_header = { ip_header with Ipv4_packet.src; dst; ttl} in
    match transport with
    | `ICMP (icmp_header, payload) ->
      begin match rewrite_icmp ~src_port icmp_header with
        | Error _ as e -> e
        | Ok new_icmp ->
          Logs.debug (fun f -> f "ICMP header rewritten to: %a" Icmpv4_packet.pp new_icmp);
          Ok (`IPv4 (new_ip_header, `ICMP (new_icmp, payload)))
      end
    | `UDP (_udp_header, udp_payload) ->
      let new_transport_header = { Udp_packet.src_port; dst_port } in
      Logs.debug (fun f -> f "UDP header rewritten to: %a" Udp_packet.pp new_transport_header);
      Ok (`IPv4 (new_ip_header, `UDP (new_transport_header, udp_payload)))
    | `TCP (tcp_header, tcp_payload) ->
      let new_transport_header = { tcp_header with Tcp.Tcp_packet.src_port; dst_port } in
      Logs.debug (fun f -> f "TCP header rewritten to: %a" Tcp.Tcp_packet.pp new_transport_header);
      Ok (`IPv4 (new_ip_header, `TCP (new_transport_header, tcp_payload)))
