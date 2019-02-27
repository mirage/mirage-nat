open Ipaddr

let src = Logs.Src.create "nat-rewrite" ~doc:"Mirage NAT packet rewriter"
module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

let (>>!=) = Rresult.R.bind

let duration_of_seconds x = Int64.mul (Int64.of_int x) 1_000_000_000L

let rewrite_ip ~src ~dst ip =
  match ip.Ipv4_packet.ttl with
  | 0 -> Error `TTL_exceeded    (* TODO: send ICMP reply *)
  | n -> Ok {ip with Ipv4_packet.ttl = n - 1; src; dst}

module Icmp_payload = struct
  let get_ports ip payload =
    if Cstruct.len payload < 8 then Error `Untranslated
    else match Ipv4_packet.Unmarshal.int_to_protocol ip.Ipv4_packet.proto with
      | Some `UDP -> Ok (`UDP, Udp_wire.get_udp_source_port payload, Udp_wire.get_udp_dest_port payload)
      | Some `TCP -> Ok (`TCP, Tcp.Tcp_wire.get_tcp_src_port payload, Tcp.Tcp_wire.get_tcp_dst_port payload)
      | _ -> Error `Untranslated

  let dup src =
    let len = Cstruct.len src in
    let copy = Cstruct.create_unsafe len in
    Cstruct.blit src 0 copy 0 len;
    copy

  let with_ports payload (sport, dport) proto =
    let payload = dup payload in
    begin match proto with
      | `UDP ->
        Udp_wire.set_udp_source_port payload sport;
        Udp_wire.set_udp_dest_port payload dport
      | `TCP ->
        Tcp.Tcp_wire.set_tcp_src_port payload sport;
        Tcp.Tcp_wire.set_tcp_dst_port payload dport
    end;
    payload
end

module Make(N : Mirage_nat.TABLE) = struct

  type t = N.t

  module type PROTOCOL = sig
    type transport
    module Table : Mirage_nat.SUBTABLE with type t := N.t

    val expiry_ns : int64

    val channel : transport -> Table.transport_channel option
    (* [channel transport] extracts the transport information from a request message.
        Returns [None] if the message is not suitable for NAT. *)

    val flip : Table.transport_channel -> Table.transport_channel
    (* [flip x] is the transport_channel we will see in a response to [x]. *)

    val rewrite : new_ip_header:Ipv4_packet.t -> transport -> Table.transport_channel -> Nat_packet.t
    (* [rewrite ip transport new_channel] is the packet [(ip, transport)] with [transport]'s channel replaced by [new_channel]. *)

    val nat_rule : Table.transport_channel -> Cstruct.uint16 -> Table.transport_channel
    (* [nat_rule channel xl_endpoint] is [channel] as it should appear after being translated by the NAT. *)

    val redirect_rule : Table.transport_channel -> final_endpoint:Mirage_nat.port -> Cstruct.uint16 ->
      (Table.transport_channel, [> `Cannot_NAT]) result
    (* [redirect_rule channel ~final_endpoint xl_endpoint] is [channel] as it should appear after being
       redirected to [final_endpoint] by the NAT. *)
  end

  module TCP = struct
    module Table = N.TCP

    type transport = [`TCP of Tcp.Tcp_packet.t * Cstruct.t]

    let expiry_ns = duration_of_seconds (60*60*24) (* TCP gets a day - this is silly *)

    let channel (`TCP (x, _)) = Some (Tcp.Tcp_packet.(x.src_port, x.dst_port))

    let flip (src_port, dst_port) = (dst_port, src_port)

    let nat_rule (_src_port, dst_port) xl_port = (xl_port, dst_port)

    let redirect_rule (_src_port, _dst_port) ~final_endpoint xl_port = Ok (xl_port, final_endpoint)

    let rewrite ~new_ip_header (`TCP (tcp_header, tcp_payload)) (src_port, dst_port) =
      let new_transport_header = { tcp_header with Tcp.Tcp_packet.src_port; dst_port } in
      Log.debug (fun f -> f "TCP header rewritten to: %a" Tcp.Tcp_packet.pp new_transport_header);
      `IPv4 (new_ip_header, `TCP (new_transport_header, tcp_payload))
  end

  module UDP = struct
    module Table = N.UDP

    type transport = [`UDP of Udp_packet.t * Cstruct.t]

    let expiry_ns = duration_of_seconds 60 (* UDP gets 60 seconds *)

    let channel (`UDP (x, _)) = Some (Udp_packet.(x.src_port, x.dst_port))

    let flip = TCP.flip
    let nat_rule = TCP.nat_rule
    let redirect_rule = TCP.redirect_rule

    let rewrite ~new_ip_header (`UDP (_, payload)) (src_port, dst_port) =
      let new_transport_header = { Udp_packet.src_port; dst_port } in
      Log.debug (fun f -> f "UDP header rewritten to: %a" Udp_packet.pp new_transport_header);
      `IPv4 (new_ip_header, `UDP (new_transport_header, payload))
  end

  module ICMP = struct
    module Table = N.ICMP

    type transport = [`ICMP of Icmpv4_packet.t * Cstruct.t]

    let expiry_ns = duration_of_seconds 120 (* RFC 5508: An ICMP Query session timer MUST NOT expire in less than 60 seconds *)

    let flip id = id

    let nat_rule _id xl_id = xl_id

    let redirect_rule _id ~final_endpoint:_ _xl_id = Error `Cannot_NAT (* mirage-nat's [`Redirect] is a port-based operation *)

    let channel (`ICMP (x, _)) = 
      match x.Icmpv4_packet.subheader with
      | Icmpv4_packet.Id_and_seq (id, _) -> Some id
      | _ -> None

    let rewrite ~new_ip_header (`ICMP (icmp, payload)) new_id =
      match icmp.Icmpv4_packet.subheader with
      | Icmpv4_packet.Id_and_seq (_, seq) ->
        let new_icmp = {icmp with Icmpv4_packet.subheader = Icmpv4_packet.Id_and_seq (new_id, seq)} in
        Log.debug (fun f -> f "ICMP header rewritten to: %a" Icmpv4_packet.pp new_icmp);
        `IPv4 (new_ip_header, `ICMP (new_icmp, payload))
      | _ -> assert false (* We already checked this in [channel] *)
  end

  let reset = N.reset

  let translate2 table (type t) (module P : PROTOCOL with type transport = t) ip (transport:P.transport) =
    match P.channel transport with
    | None -> Lwt.return (Error `Untranslated)
    | Some transport_channel ->
      let src = ip.Ipv4_packet.src in
      let dst = ip.Ipv4_packet.dst in
      P.Table.lookup table (src, dst, transport_channel) >|= function
      | Some (_expiry, (src, dst, new_transport_channel)) ->
        rewrite_ip ~src ~dst ip >>!= fun new_ip_header ->
        Ok (P.rewrite ~new_ip_header transport new_transport_channel)
      | None ->
        Error `Untranslated

  let icmp_error table orig_ip_pub ip icmp payload payload_len =
    match Icmp_payload.get_ports orig_ip_pub payload with
    | Error _ as e -> Lwt.return e
    | Ok (proto, src_port, dst_port) ->
      Log.debug (fun f -> f "ICMP error is for %a src_port=%d dst_port=%d"
                    Ipv4_packet.pp orig_ip_pub src_port dst_port
                );
      (* Reverse src and dst because we want to treat this the same way we would
         have treated a normal response. *)
      let channel = orig_ip_pub.Ipv4_packet.dst, orig_ip_pub.Ipv4_packet.src, (dst_port, src_port) in
      begin
        match proto with
        | `TCP -> N.TCP.lookup table channel
        | `UDP -> N.UDP.lookup table channel
      end >|= function
      | Some (_expiry, (new_src, new_dst, (new_sport, new_dport))) ->
        rewrite_ip ~src:new_src ~dst:new_dst ip >>!= fun ip ->
        let orig_ip_priv = { orig_ip_pub with Ipv4_packet.dst = new_src; src = new_dst } in
        let payload = Icmp_payload.with_ports payload (new_dport, new_sport) proto in
        let ip_struct = Ipv4_packet.Marshal.make_cstruct orig_ip_priv ~payload_len in
        let error_priv = Cstruct.concat [ip_struct; payload] in
        Ok (`IPv4 (ip, (`ICMP (icmp, error_priv))))
      | _ ->
        Error `Untranslated


  let translate table packet =
    MProf.Trace.label "Nat_rewrite.translate";
    match packet with
    | `IPv4 (ip, (`TCP _ as transport)) -> translate2 table (module TCP) ip transport
    | `IPv4 (ip, (`UDP _ as transport)) -> translate2 table (module UDP) ip transport
    | `IPv4 (ip, (`ICMP (icmp,_) as transport)) when Nat_packet.icmp_type icmp = `Query -> translate2 table (module ICMP) ip transport
    | `IPv4 (ip, `ICMP (icmp, payload)) ->
      match Ipv4_packet.Unmarshal.of_cstruct payload with
      | Error _ -> Lwt.return @@ Error `Untranslated
      | Ok (orig_ip, data_start) ->
        icmp_error table orig_ip ip icmp data_start (Cstruct.len payload)   

  let add table ~now packet (xl_host, xl_port) mode =
    let `IPv4 (ip_header, transport) = packet in
    let check_scope ip =
      match Ipaddr.scope (V4 ip) with
      | Global | Organization -> true
      | _ -> false
    in
    let (src, dst) = Ipv4_packet.(ip_header.src, ip_header.dst) in
    match check_scope src, check_scope dst with
    | false, _ | _, false -> Lwt.return (Error `Cannot_NAT)
    | true, true ->
      let add2 (type t) (module P : PROTOCOL with type transport = t) (t:t) =
        let expiry = Int64.add now P.expiry_ns in
        match P.channel t with
        | None -> Lwt.return (Error `Cannot_NAT)
        | Some transport_channel ->
          let add_mapping (final_dst, translated_transport) =
            let request_mapping = (src, dst, transport_channel), (xl_host, final_dst, translated_transport) in
            let response_mapping = (final_dst, xl_host, P.flip translated_transport), (dst, src, P.flip transport_channel) in
            P.Table.insert table ~expiry [request_mapping; response_mapping]
          in
          match mode with
          | `NAT -> add_mapping (dst, P.nat_rule transport_channel xl_port)
          | `Redirect (final_dst, final_endpoint) ->
            match P.redirect_rule transport_channel ~final_endpoint xl_port with
            | Ok translated_request_transport -> add_mapping (final_dst, translated_request_transport)
            | Error _ as e -> Lwt.return e
      in
      match transport with
      | `TCP _ as transport  -> add2 (module TCP) transport
      | `UDP _ as transport  -> add2 (module UDP) transport
      | `ICMP (icmp, _) as transport when Nat_packet.icmp_type icmp = `Query -> add2 (module ICMP) transport
      | `ICMP _ -> Lwt.return (Error `Cannot_NAT)

end
