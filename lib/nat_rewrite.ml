open Ipaddr
open Mirage_nat

module Make(Nat_table : Mirage_nat.Lookup) : sig
  include Mirage_nat.S with type config = Nat_table.config
end = struct
  let src = Logs.Src.create "nat-rewrite" ~doc:"Mirage NAT packet rewriter"
  module Log = (val Logs.src_log src : Logs.LOG)

  module N = Nat_table
  type t = N.t
  type config = Nat_table.config

  type insert_result =
    | Ok
    | Overlap
    | Unparseable

  let empty (config : N.config) = N.empty config

  let ports_of_tcp_or_udp = function
    | `TCP (x, _) -> Tcp.Tcp_packet.(x.src_port, x.dst_port)
    | `UDP (x, _) -> Udp_packet.(x.src_port, x.dst_port)

  let translate table (packet:Nat_packet.t) =
    MProf.Trace.label "Nat_rewrite.translate";
    let `IPv4 (ip, transport) = packet in
    let proto = match transport with
      | `TCP _ -> Tcp
      | `UDP _ -> Udp
    in
    let sport, dport = ports_of_tcp_or_udp transport in
    let (>>=) = Lwt.bind in
    (* got everything; do the lookup *)
    N.lookup table proto ((V4 ip.Ipv4_packet.src), sport) ((V4 ip.Ipv4_packet.dst), dport) >>= function
    | None ->
      Lwt.return Untranslated (* don't autocreate new entries *)
    | Some (_expiry, ((V4 new_src, new_sport), (V4 new_dst, new_dport))) ->
      (* TODO: we should probably refuse to pass TTL = 0 and instead send an
          ICMP message back to the sender *)
      match Nat_decompose.rewrite_packet packet ~src:(new_src, new_sport) ~dst:(new_dst, new_dport) with
      | Ok packet -> Lwt.return (Translated packet)
      | Error s -> Log.warn (fun f -> f "Translating a packet failed: %s; packet content: %a" s Nat_packet.pp packet);
        Lwt.return Untranslated

  let add_entry mode table packet
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    let `IPv4 (ip_header, transport) = packet in
    match transport with
    | `TCP ({Tcp.Tcp_packet.src_port; dst_port; _}, _)
    | `UDP ({Udp_packet.src_port; dst_port; _}, _) ->
      let check_scope ip =
        match Ipaddr.scope ip with
        | Global | Organization -> true
        | _ -> false
      in
      let (src, dst) = Ipv4_packet.(V4 ip_header.src, V4 ip_header.dst) in
      match check_scope src, check_scope dst with
      | false, _ | _, false -> Lwt.return Unparseable
      | true, true ->
        let (>>=) = Lwt.bind in
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
        N.insert table expiration_window proto entries >>= function
        | Some t -> Lwt.return Ok
        | None -> Lwt.return Overlap

  let add_redirect table packet
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    add_entry Redirect table packet
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port)

  let add_nat table packet (xl_ip, xl_port) =
    add_entry Nat table packet (xl_ip, xl_port) (xl_ip, xl_port)

end
