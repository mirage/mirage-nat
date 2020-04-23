open Ipaddr

let src = Logs.Src.create "nat-rewrite" ~doc:"Mirage NAT packet rewriter"
module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

let (>>!=) = Rresult.R.bind

let rewrite_ip ~src ~dst ip =
  match ip.Ipv4_packet.ttl with
  | 0 -> Error `TTL_exceeded    (* TODO: send ICMP reply *)
  | n -> Ok {ip with Ipv4_packet.ttl = n - 1; src; dst}

module Icmp_payload = struct
  let get_encapsulated_packet_channel ip payload =
    if Cstruct.len payload < 8 then (
      Log.debug (fun m -> m "Payload too short to analyze");
      Error `Untranslated)
    else match Ipv4_packet.Unmarshal.int_to_protocol ip.Ipv4_packet.proto with
      | Some `UDP -> Ok (`UDP (Udp_wire.get_udp_source_port payload, Udp_wire.get_udp_dest_port payload))
      | Some `TCP -> Ok (`TCP (Tcp.Tcp_wire.get_tcp_src_port payload, Tcp.Tcp_wire.get_tcp_dst_port payload))
      | Some `ICMP -> Ok (`ICMP (Icmpv4_wire.get_icmpv4_id payload))
      | _ -> Error `Untranslated

  let dup src =
    let len = Cstruct.len src in
    let copy = Cstruct.create_unsafe len in
    Cstruct.blit src 0 copy 0 len;
    copy

  let with_channel payload channel =
    let payload = dup payload in
    begin match channel with
      | `UDP (sport, dport) ->
        Udp_wire.set_udp_source_port payload sport;
        Udp_wire.set_udp_dest_port payload dport
      | `TCP (sport, dport) ->
        Tcp.Tcp_wire.set_tcp_src_port payload sport;
        Tcp.Tcp_wire.set_tcp_dst_port payload dport
      | `ICMP id ->
        (* in the case of TCP and UDP, we can't fix the checksum here
           because we need to also include information on the pseudoheader,
           so we do it later.  But for ICMP, we can do it here (and should,
           since this is our last chance to get our hands on the payload). *)
        Icmpv4_wire.set_icmpv4_id payload id;
        Icmpv4_wire.set_icmpv4_csum payload 0x0000;
        Icmpv4_wire.set_icmpv4_csum payload (Tcpip_checksum.ones_complement payload)
    end;
    payload

end

module Make(N : Mirage_nat.TABLE) = struct

  type t = N.t

  module type PROTOCOL = sig
    type transport
    module Table : Mirage_nat.SUBTABLE with type t := N.t

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
  let remove_connections = N.remove_connections

  let translate_by_transport table (type t) (module P : PROTOCOL with type transport = t) ip (transport:P.transport) =
    match P.channel transport with
    | None ->
      Log.debug (fun m -> m "No transport channel");
      Lwt.return (Error `Untranslated)
    | Some transport_channel ->
      let src = ip.Ipv4_packet.src in
      let dst = ip.Ipv4_packet.dst in
      P.Table.lookup table (src, dst, transport_channel) >|= function
      | Some (src, dst, new_transport_channel) ->
        rewrite_ip ~src ~dst ip >>!= fun new_ip_header ->
        Ok (P.rewrite ~new_ip_header transport new_transport_channel)
      | None ->
        Log.debug (fun m -> m "No rule matching channel");
        Error `Untranslated

(* given parameters of an ICMP error message with an embedded IPv4 packet (with transport header),
   translate the error message using the relevant NAT rules so it can be delivered to the client
   on our local network.

   The message looks like:

   +------------------------------------------------------+
   | Outer IPv4 header: external src -> public NAT IP     |
   +------------------------------------------------------+
   |       ICMP header: this is an error message          |
   +------------------------------------------------------+
   | Inner IPV4 header: public NAT IP -> external dst     |
   |    note that the inner IPv4 payload is likely        |
   |    truncated, but the inner IPv4 header's length     |
   |    field will reflect the original packet size       |
   +------------------------------------------------------+
   | TCP/UDP header: public NAT srcport -> external dport |
   +------------------------------------------------------+

   We want to translate it to:

   +------------------------------------------------------+
   | Outer IPv4 header: external src -> private client IP |
   +------------------------------------------------------+
   |       ICMP header: this is an error message          |
   +------------------------------------------------------+
   | Inner IPV4 header: private client IP -> external dst |
   |    note that the inner IPv4 payload is likely        |
   |    truncated, but the inner IPv4 header's length     |
   |    field will reflect the original packet size       |
   +------------------------------------------------------+
   | TCP/UDP header: client srcport -> external dport     |
   +------------------------------------------------------+

   *)
  let translate_icmp_error table ~outer_ip ~icmp ~icmp_payload ~inner_ip ~inner_transport_header =
    let rewrite_packet ~new_outer_src ~new_outer_dst ~new_inner_src ~new_inner_dst ~channel =
      (* rewrite both the inner and outer IPv4 headers *)
      (* but only call `rewrite_ip` on the outer header, since this decrements the TTL,
         and while this is appropriate for the outer IPv4 header,
         we should preserve all non-address fields (including the TTL) in the inner IPv4 header. *)
       rewrite_ip ~src:new_outer_src ~dst:new_outer_dst outer_ip >>!= fun translated_outer_ip ->
       let translated_inner_ip = { inner_ip with Ipv4_packet.src = new_inner_src; dst = new_inner_dst } in
       (* also, change the encapsulated transport header's port numbers *)
       let translated_inner_transport_payload =
         Icmp_payload.with_channel inner_transport_header channel in
       (* in order to preserve the IPv4 total length from the original message
        * (which might be incorrect due to truncation of the ICMP error message),
        * retrieve this value from the ICMP payload, which is also the inner IP header.
        * This is replicating some non-exposed logic from the tcpip library's Ipv4_packet module. *)
       let original_inner_ipv4_header_length = 20 + (Cstruct.len inner_ip.options) in
       let original_inner_ipv4_total_length = Ipv4_wire.get_ipv4_len icmp_payload in
       let original_inner_ipv4_payload_length = original_inner_ipv4_total_length - original_inner_ipv4_header_length in
       (* Now we can reassemble the translated inner packet
        * with the correct IP and port information. *)
       let inner_ip_struct = Ipv4_packet.Marshal.make_cstruct
           translated_inner_ip ~payload_len:original_inner_ipv4_payload_length in
       let translated_icmp_payload = Cstruct.concat
           [inner_ip_struct; translated_inner_transport_payload] in
       (* Encapsulate the inner packet in the translated outer packet. *)
       Ok (`IPv4 (translated_outer_ip, (`ICMP (icmp, translated_icmp_payload))))
    in
    (* It is necessary to take the inner IPv4 source and destination address,
       since the outer IPv4 header may come from an intermediate router which
       won't be represented in the table. *)
    (* Since we are looking up the information from the inner header, we will need to
       switch the source and destination to get the correct translation from the NAT
       table. *)
    (* We also need to retain the original source address from the outer IPv4 packet,
       as this may have come from an intermediate router. *)
    (* When checking for an associated entry in the NAT table, we want to use the port (or ID, for ICMP)
       information from the inner transport header.  In the TCP/UDP case, these ports then also
       need to be looked up in reverse order. *)
    match Icmp_payload.get_encapsulated_packet_channel inner_ip inner_transport_header with
    | Error _ as e -> Lwt.return e
    | Ok (`ICMP id) -> begin
      (* in this case, we still (hopefully) have a channel in the inner layer on which to match,
         it's just not port-based *)
      let channel = inner_ip.Ipv4_packet.dst, inner_ip.Ipv4_packet.src, id in
      N.ICMP.lookup table channel >|= function
      | None ->
        Log.debug (fun f -> f "ICMP error message encapsulating ICMP query with id %d has no matching entry \
                               in the ICMP NAT table; cannot translate this packet" id);
        Error `Untranslated
      | Some (new_src, new_dst, new_id) ->
        rewrite_packet ~new_outer_src:outer_ip.Ipv4_packet.src ~new_outer_dst:new_dst
          ~new_inner_src:new_dst ~new_inner_dst:new_src ~channel:(`ICMP new_id)
    end
      (* The port info is only available in the inner transport header, but it also
         must be reversed in the lookup call in order to get the correct translation. *)
    | Ok (`TCP (src_port, dst_port)) -> begin
      let channel = inner_ip.Ipv4_packet.dst, inner_ip.Ipv4_packet.src, (dst_port, src_port) in
      N.TCP.lookup table channel >|= function
      | Some (new_src, new_dst, (new_sport, new_dport)) ->
        rewrite_packet ~new_outer_src:outer_ip.Ipv4_packet.src ~new_outer_dst:new_dst
          ~new_inner_src:new_dst ~new_inner_dst:new_src
          ~channel:(`TCP (new_dport, new_sport))
      | None -> Error `Untranslated
    end
    | Ok (`UDP (src_port, dst_port)) ->
       let channel = inner_ip.Ipv4_packet.dst, inner_ip.Ipv4_packet.src, (dst_port, src_port) in
       N.UDP.lookup table channel >|= function
       | Some (new_src, new_dst, (new_sport, new_dport)) ->
        rewrite_packet ~new_outer_src:outer_ip.Ipv4_packet.src ~new_outer_dst:new_dst
          ~new_inner_src:new_dst ~new_inner_dst:new_src
          ~channel:(`UDP (new_dport, new_sport))
       | None -> Error `Untranslated


  let translate table packet =
    MProf.Trace.label "Nat_rewrite.translate";
    match packet with
    | `IPv4 (ip, (`TCP _ as transport)) -> translate_by_transport table (module TCP) ip transport
    | `IPv4 (ip, (`UDP _ as transport)) -> translate_by_transport table (module UDP) ip transport
    | `IPv4 (ip, (`ICMP (icmp,_) as transport)) when Nat_packet.icmp_type icmp = `Query ->
      translate_by_transport table (module ICMP) ip transport
    | `IPv4 (outer_ip, `ICMP (icmp, icmp_payload)) ->
      match Ipv4_packet.Unmarshal.header_of_cstruct icmp_payload with
      | Error _ ->
        Log.debug (fun m -> m "Failed to read encapsulated IPv4 packet in ICMP payload: does not parse");
        Lwt.return @@ Error `Untranslated
      | Ok (inner_ip, transport_header_start) ->
        let inner_transport_header = Cstruct.shift icmp_payload transport_header_start in
        translate_icmp_error table ~outer_ip ~inner_ip ~icmp ~icmp_payload ~inner_transport_header

  let add table packet (xl_host, xl_port) mode =
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
        match P.channel t with
        | None -> Lwt.return (Error `Cannot_NAT)
        | Some transport_channel ->
          let add_mapping (final_dst, translated_transport) =
            let request_mapping = (src, dst, transport_channel), (xl_host, final_dst, translated_transport) in
            let response_mapping = (final_dst, xl_host, P.flip translated_transport), (dst, src, P.flip transport_channel) in
            P.Table.insert table [request_mapping; response_mapping]
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
