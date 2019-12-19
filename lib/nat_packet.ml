[@@@ocaml.warning "-39"]

type t =
  [`IPv4 of Ipv4_packet.t * [ `TCP of Tcp.Tcp_packet.t * Cstruct.t
                            | `UDP of Udp_packet.t * Cstruct.t
                            | `ICMP of Icmpv4_packet.t * Cstruct.t
                            ]
  ]
[@@deriving eq]

[@@@ocaml.warning "+39"]

type error = Format.formatter -> unit

let pp_error f e = e f

let icmp_type header =
  let open Icmpv4_wire in
  match header.Icmpv4_packet.ty with
  | Timestamp_request
  | Timestamp_reply
  | Information_request
  | Information_reply
  | Echo_request
  | Echo_reply -> `Query
  | Source_quench
  | Redirect
  | Time_exceeded
  | Parameter_problem
  | Destination_unreachable -> `Error

let of_ipv4_packet cache ~now packet : (t option, error) result =
  match Ipv4_packet.Unmarshal.of_cstruct packet with
  | Error e ->
    Error (fun f -> Fmt.pf f "Failed to parse IPv4 packet: %s@.%a" e Cstruct.hexdump_pp packet)
  | Ok (ip_packet, payload) ->
    match Fragments.process cache now ip_packet payload with
    | None -> Ok None
    | Some (ip, transport) ->
      match Ipv4_packet.(Unmarshal.int_to_protocol ip.proto) with
      | Some `TCP ->
        begin match Tcp.Tcp_packet.Unmarshal.of_cstruct transport with
          | Error e ->
            Error (fun f -> Fmt.pf f "Failed to parse TCP packet: %s@.%a" e Cstruct.hexdump_pp transport)
          | Ok (tcp, payload) -> Ok (Some (`IPv4 (ip, `TCP (tcp, payload))))
        end
      | Some `UDP ->
        begin match Udp_packet.Unmarshal.of_cstruct transport with
          | Error e ->
            Error (fun f -> Fmt.pf f "Failed to parse UDP packet: %s@.%a" e Cstruct.hexdump_pp transport)
          | Ok (udp, payload) -> Ok (Some (`IPv4 (ip, `UDP (udp, payload))))
        end
      | Some `ICMP ->
        begin match Icmpv4_packet.Unmarshal.of_cstruct transport with
          | Error e ->
            Error (fun f -> Fmt.pf f "Failed to parse ICMP packet: %s@.%a" e Cstruct.hexdump_pp transport)
          | Ok (header, payload) -> Ok (Some (`IPv4 (ip, `ICMP (header, payload))))
        end
      | _ ->
        Error (fun f -> Fmt.pf f "Ignoring non-TCP/UDP packet: %a" Ipv4_packet.pp ip)

let of_ethernet_frame cache ~now frame =
  match Ethernet_packet.Unmarshal.of_cstruct frame with
  | Error e ->
    Error (fun f -> Fmt.pf f "Failed to parse ethernet frame: %s@.%a" e Cstruct.hexdump_pp frame)
  | Ok (eth, packet) ->
    match eth.Ethernet_packet.ethertype with
    | `ARP | `IPv6 ->
      Error (fun f -> Fmt.pf f "Ignoring a non-IPv4 frame: %a" Cstruct.hexdump_pp frame)
    | `IPv4 -> of_ipv4_packet cache ~now packet

let decompose_transport = function
  | `ICMP (_, icmp_payload) -> Icmpv4_wire.sizeof_icmpv4, (Cstruct.len icmp_payload)
  | `UDP (_, udp_payload) -> Udp_wire.sizeof_udp, (Cstruct.len udp_payload)
  | `TCP (tcp_header, tcp_payload) ->
    let options_length = Tcp.Options.lenv tcp_header.Tcp.Tcp_packet.options in
    (Tcp.Tcp_wire.sizeof_tcp + options_length), (Cstruct.len tcp_payload)

let to_cstruct ?(mtu = 1500) ((`IPv4 (ip, transport)):t) =
  let {Ipv4_packet.src; dst; _} = ip in
  (* Calculate required buffer size *)
  let transport_header_len, _ = decompose_transport transport in
  (* Create buffers representing the transport header, and return it in a list with the payload.
     We do the transport layer first so that we calculate the correct checksum when we
     write the IP layer. *)
  let transport_hdr, transport_payload =
    match transport with
    | `ICMP (icmp_header, payload) ->
      let transport_header = Icmpv4_packet.Marshal.make_cstruct icmp_header ~payload in
      Logs.debug (fun f -> f "ICMP header written: %a" Cstruct.hexdump_pp transport_header);
      transport_header, payload
    | `UDP (udp_header, udp_payload) ->
      let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP (Cstruct.len udp_payload + Udp_wire.sizeof_udp) in
      let transport_header = Udp_packet.Marshal.make_cstruct
        ~pseudoheader udp_header
        ~payload:udp_payload in
      Logs.debug (fun f -> f "UDP header written: %a" Cstruct.hexdump_pp transport_header);
      transport_header, udp_payload
    | `TCP (tcp_header, tcp_payload) ->
      let options_length = transport_header_len - Tcp.Tcp_wire.sizeof_tcp in
      let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`TCP (Tcp.Tcp_wire.sizeof_tcp + options_length + Cstruct.len tcp_payload) in
      let transport_header = Tcp.Tcp_packet.Marshal.make_cstruct
        ~pseudoheader tcp_header
        ~payload:tcp_payload in
      Logs.debug (fun f -> f "TCP header written: %a" Cstruct.hexdump_pp transport_header);
      transport_header, tcp_payload
  in
  let payload = Cstruct.append transport_hdr transport_payload in
  let plen = Cstruct.len payload in
  let pmtu = mtu - Ipv4_wire.sizeof_ipv4 in
  let need_fragment = plen > pmtu in
  if need_fragment && ip.Ipv4_packet.off land 0x4000 > 0 then
    Error (fun f -> Fmt.pf f "would need to fragment, but don't fragment is set")
  else
    let ip = if need_fragment then { ip with off = 0x2000 } else ip in
    let first, rest = if need_fragment then Cstruct.split payload pmtu else payload, Cstruct.empty in
    let ip_header = Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.len first) ip in
    let frags = if need_fragment then Fragments.fragment ~mtu ip rest else [] in
    Ok (Cstruct.append ip_header first :: frags)

let into_cstruct ((`IPv4 (ip, transport)):t) full_buffer =
  let open Rresult.R in
  let {Ipv4_packet.src; dst; _} = ip in
  let mtu = Cstruct.len full_buffer in
  (* Calculate required buffer size *)
  let ip_header_len = Ipv4_wire.sizeof_ipv4 + Cstruct.len ip.Ipv4_packet.options in
  let transport_header_len, transport_payload_len = decompose_transport transport in
  let total_len = ip_header_len + transport_header_len + transport_payload_len in
  let need_fragment = total_len > mtu in
  (* short way out: don't fragment set and buffer too small *)
  let dont_fragment = ip.off land 0x4000 > 0 in
  if dont_fragment && need_fragment then
    Error (fun f -> Fmt.pf f "should send ICMP error back to src, would_fragment")
  else begin
    (* otherwise: first packet, and use Fragments to produce other ones *)
    (* copy the payload into the provided buffer, then write the correct transport header *)
    (* let's assume transport header fits into first packet *)
    assert (mtu > ip_header_len + transport_header_len);
    let this_transport_payload_len =
      min transport_payload_len (mtu - ip_header_len - transport_header_len)
    in
    let write_transport_header_and_payload transport =
      let payload_start = ip_header_len + transport_header_len in
      match transport with
      | `ICMP (icmp_header, payload) -> begin
          let this, left = Cstruct.split payload this_transport_payload_len in
          Cstruct.blit this 0 full_buffer payload_start (Cstruct.len this);
          match Icmpv4_packet.Marshal.into_cstruct icmp_header ~payload (Cstruct.shift full_buffer ip_header_len) with
          | Error s -> Error (fun f -> Fmt.pf f "Error writing ICMPv4 packet: %s" s);
          | Ok () ->
            Logs.debug (fun f -> f "ICMP header and payload written: %a" Cstruct.hexdump_pp (Cstruct.shift full_buffer ip_header_len));
            Ok (transport_header_len + this_transport_payload_len, left)
        end
      | `UDP (udp_header, udp_payload) -> begin
          let this, left = Cstruct.split udp_payload this_transport_payload_len in
          Cstruct.blit this 0 full_buffer payload_start this_transport_payload_len;
          let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP (Cstruct.len udp_payload + Udp_wire.sizeof_udp) in
          match Udp_packet.Marshal.into_cstruct
                  ~pseudoheader ~payload:udp_payload udp_header
                  (Cstruct.shift full_buffer ip_header_len) with
          | Error s -> Error (fun f -> Fmt.pf f "Error writing UDP packet: %s" s);
          | Ok () ->
            Logs.debug (fun f -> f "UDP header written: %a" Cstruct.hexdump_pp (Cstruct.sub full_buffer ip_header_len transport_header_len));
            Ok (transport_header_len + this_transport_payload_len, left)
        end
      | `TCP (tcp_header, tcp_payload) -> begin
          let this, left = Cstruct.split tcp_payload this_transport_payload_len in
          Cstruct.blit this 0 full_buffer payload_start this_transport_payload_len;
          (* and now transport header *)
          let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`TCP
              (transport_header_len + transport_payload_len) in
          match Tcp.Tcp_packet.Marshal.into_cstruct
                  ~pseudoheader tcp_header
                  ~payload:tcp_payload (Cstruct.shift full_buffer ip_header_len) with
          | Error s -> Error (fun f -> Fmt.pf f "Error writing TCP packet: %s" s);
          | Ok written ->
            Logs.debug (fun f -> f "TCP header written: %a" Cstruct.hexdump_pp (Cstruct.sub full_buffer ip_header_len transport_header_len));
            Ok (written + this_transport_payload_len, left)
        end
    in
    write_transport_header_and_payload transport >>= fun (written, leftover) ->
    let need_fragment = Cstruct.len leftover > 0 in
    let off = if need_fragment then 0x2000 else 0x0000 in
    let ip' = { ip with off } in
    (* Write the IP header into the first part of the buffer. *)
    match Ipv4_packet.Marshal.into_cstruct ~payload_len:written ip' full_buffer with
    | Error s -> Error (fun f -> Fmt.pf f "Error writing IPv4 header: %s" s)
    | Ok () ->
      Logs.debug (fun f -> f "IPv4 header written: %a" Cstruct.hexdump_pp (Cstruct.sub full_buffer 0 ip_header_len));
      let fragments =
        if need_fragment then Fragments.fragment ~mtu ip' leftover else []
      in
      Ok (written + ip_header_len, fragments)
  end

let pp_icmp f payload = Cstruct.hexdump_pp f payload

let pp_transport f = function
  | `ICMP (icmp, payload) ->
    Fmt.pf f "%a with payload %a"
      Icmpv4_packet.pp icmp
      pp_icmp payload
  | `TCP (tcp, payload) ->
    Fmt.pf f "%a with payload %a"
      Tcp.Tcp_packet.pp tcp
      Cstruct.hexdump_pp payload
  | `UDP (udp, payload) ->
    Fmt.pf f "%a with payload %a"
      Udp_packet.pp udp
      Cstruct.hexdump_pp payload

let pp f = function
  | `IPv4 (ip, transport) ->
    Fmt.pf f "%a %a"
      Ipv4_packet.pp ip
      pp_transport transport
