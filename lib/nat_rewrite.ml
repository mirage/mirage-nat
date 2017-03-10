open Ipaddr
open Mirage_nat

open Lwt.Infix

let rewrite_icmp ~src_port icmp =
  match icmp.Icmpv4_packet.subheader with
  | Icmpv4_packet.Id_and_seq (_, seq) ->
    Ok {icmp with Icmpv4_packet.subheader = Icmpv4_packet.Id_and_seq (src_port, seq)}
  | _ ->
    Error `Untranslated

let rewrite_packet packet ~src:(src, src_port) ~dst:(dst,dst_port) =
  let `IPv4 (ip_header, transport) = packet in
  match Ipv4_packet.(ip_header.ttl) with
  | 0 -> Error `TTL_exceeded
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

module Make(Nat_table : Mirage_nat.Lookup) = struct
  let src = Logs.Src.create "nat-rewrite" ~doc:"Mirage NAT packet rewriter"
  module Log = (val Logs.src_log src : Logs.LOG)

  module N = Nat_table
  type t = N.t

  let reset = N.reset

  let ports_of_ip = function
    | `TCP (x, _) -> Some Tcp.Tcp_packet.(x.src_port, x.dst_port)
    | `UDP (x, _) -> Some Udp_packet.(x.src_port, x.dst_port)
    | `ICMP (x, _) ->
      match x.Icmpv4_packet.subheader with
      | Icmpv4_packet.Id_and_seq (id, _) -> Some (id, id)
      | _ -> None

  let translate2 table proto packet =
    let `IPv4 (ip, transport) = packet in
    match ports_of_ip transport with
    | None -> Lwt.return (Error `Untranslated)
    | Some (sport, dport) -> 
      let (>>=) = Lwt.bind in
      (* got everything; do the lookup *)
      N.lookup table proto ~source:((V4 ip.Ipv4_packet.src), sport) ~destination:((V4 ip.Ipv4_packet.dst), dport) >>= function
      | Some (_expiry, ((V4 new_src, new_sport), (V4 new_dst, new_dport))) ->
        (* TODO: we should probably refuse to pass TTL = 0 and instead send an
            ICMP message back to the sender *)
        begin match rewrite_packet packet ~src:(new_src, new_sport) ~dst:(new_dst, new_dport) with
        | Ok packet -> Lwt.return (Ok packet)
        | Error e ->
          Log.warn (fun f -> f "Translating a packet failed: %a; packet content: %a"
                       Mirage_nat.pp_error e
                       Nat_packet.pp packet);
          Lwt.return (Error e)
        end
      | _ ->
        Lwt.return (Error `Untranslated) (* don't autocreate new entries *)

  let get_ports ip payload =
    if Cstruct.len payload < 8 then Error `Untranslated
    else match Ipv4_packet.Unmarshal.int_to_protocol ip.Ipv4_packet.proto with
      | Some `UDP -> Ok (Udp, Udp_wire.get_udp_source_port payload, Udp_wire.get_udp_dest_port payload)
      | Some `TCP -> Ok (Tcp, Tcp.Tcp_wire.get_tcp_src_port payload, Tcp.Tcp_wire.get_tcp_dst_port payload)
      | _ -> Error `Untranslated

  let dup src =
    let len = Cstruct.len src in
    let copy = Cstruct.create_unsafe len in
    Cstruct.blit src 0 copy 0 len;
    copy

  let with_ports payload (sport, dport) proto =
    let payload = dup payload in
    begin match proto with
      | Udp ->
        Udp_wire.set_udp_source_port payload sport;
        Udp_wire.set_udp_dest_port payload dport
      | Tcp ->
        Tcp.Tcp_wire.set_tcp_src_port payload sport;
        Tcp.Tcp_wire.set_tcp_dst_port payload dport
      | Icmp ->
        assert false
    end;
    payload

  let translate table (packet:Nat_packet.t) =
    MProf.Trace.label "Nat_rewrite.translate";
    let `IPv4 (ip, transport) = packet in
    match transport with
    | `TCP _ -> translate2 table Tcp packet
    | `UDP _ -> translate2 table Udp packet
    | `ICMP (_, `Query _) -> translate2 table Icmp packet
    | `ICMP (icmp, `Error (orig_ip_pub, payload, payload_len)) ->
      match get_ports orig_ip_pub payload with
      | Error _ as e -> Lwt.return e
      | Ok (proto, src_port, dst_port) ->
        Log.debug (fun f -> f "ICMP error is for %a src_port=%d dst_port=%d"
                     Ipv4_packet.pp orig_ip_pub src_port dst_port
                 );
        (* Reverse src and dst because we want to treat this the same way we would
           have treated a normal response. *)
        let source = Ipaddr.V4 orig_ip_pub.Ipv4_packet.dst, dst_port in
        let destination = Ipaddr.V4 orig_ip_pub.Ipv4_packet.src, src_port in
        N.lookup table proto ~source ~destination >>= function
        | Some (_expiry, ((V4 new_src, new_sport), (V4 new_dst, new_dport))) ->
          begin match ip.Ipv4_packet.ttl with
          | 0 -> Lwt.return (Error `TTL_exceeded)
          | ttl ->
            let ttl = ttl - 1 in
            let ip = { ip with Ipv4_packet.src = new_src; dst = new_dst; ttl } in
            let orig_ip_priv = { orig_ip_pub with Ipv4_packet.dst = new_src; src = new_dst } in
            let payload = with_ports payload (new_dport, new_sport) proto in
            let error_priv = `Error (orig_ip_priv, payload, payload_len) in
            let packet : Nat_packet.t = `IPv4 (ip, `ICMP (icmp, error_priv)) in
            Lwt.return (Ok packet)
          end
        | _ -> Lwt.return (Error `Untranslated)

  let add_entry mode table packet
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    let `IPv4 (ip_header, transport) = packet in
    let check_scope ip =
      match Ipaddr.scope ip with
      | Global | Organization -> true
      | _ -> false
    in
    let (src, dst) = Ipv4_packet.(V4 ip_header.src, V4 ip_header.dst) in
    match check_scope src, check_scope dst with
    | false, _ | _, false -> Lwt.return (Error `Cannot_NAT)
    | true, true ->
      match transport with
      | `ICMP _ when mode = Redirect -> Lwt.return (Error (`Cannot_NAT))
      | `ICMP _ ->
        begin
          match ports_of_ip transport with
          | None -> Lwt.return (Error `Cannot_NAT)
          | Some (id, _) ->
            let open Nat_translations in
            let entries =
              map_redirect
                ~left:(src, id)
                ~translate_left:(dst, id)
                ~translate_right:(other_xl_ip, other_xl_port)
                ~right:(dst, other_xl_port)
            in
            (* RFC 5508: An ICMP Query session timer MUST NOT expire in less than 60 seconds *)
            let expiration_window = 120L in
            let proto = Icmp in
            N.insert table expiration_window proto entries
        end
    | `TCP _ | `UDP _ as transport ->
      match ports_of_ip transport with
      | None -> Lwt.return (Error `Cannot_NAT)
      | Some (src_port, dst_port) ->
        let open Nat_translations in
        let entries = match mode with
          | Nat ->
            map_nat
              ~left:(src, src_port)
              ~right:(dst, dst_port)
              ~translate_left:(other_xl_ip, other_xl_port)
          | Redirect ->
            map_redirect
              ~left:(src, src_port)
              ~right:(final_destination_ip, final_destination_port)
              ~translate_left:(dst, dst_port)
              ~translate_right:(other_xl_ip, other_xl_port)
        in
        let expiration_window =
          (* TODO: this is silly in the case of TCP *)
          match transport with
          | `UDP _ -> Int64.of_int 60 (* UDP gets 60 seconds *)
          | `TCP _ -> Int64.of_int (60*60*24) (* TCP gets a day *)
        in
        let proto = match transport with
          | `TCP _ -> Tcp
          | `UDP _ -> Udp
        in
        N.insert table expiration_window proto entries

  let add_redirect table packet
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    add_entry Redirect table packet
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port)

  let add_nat table packet (xl_ip, xl_port) =
    add_entry Nat table packet (xl_ip, xl_port) (xl_ip, xl_port)

end
