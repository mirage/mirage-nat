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

  let translate table frame =
    MProf.Trace.label "Nat_rewrite.translate";
    (* TODO: this is not correct for IPv6 *)
    (* TODO: it's not clear to me whether we need to do this, since most users
       will be sending packets via IP.write, which itself calculates and inserts
       the proper checksum before sending the packet. *)
    match Nat_decompose.decompose frame with
    | Result.Error s -> Log.debug (fun f -> f "parsing of a packet presented for translation failed: %s" s);
      Lwt.return Untranslated (* un-NATtable packet; drop it like it's hot *)
    | Result.Ok { ethernet; network; transport } ->
       match network, (Nat_decompose.ports transport) with
      | Ipv6 _, _ -> Log.debug (fun f -> f "Ignoring an IPv6 packet"); Lwt.return Untranslated (* TODO, obviously *)
      | Ipv4 _, None -> Log.debug (fun f -> f "Ignoring a non-TCP/UDP packet: %a" Cstruct.hexdump_pp frame);
        Lwt.return Untranslated (* TODO: don't just drop all packets that aren't TCP/UDP *)
      | Ipv4 (ip_header, ip_payload), Some (proto, transport, sport, dport) ->
        let (>>=) = Lwt.bind in
        (* got everything; do the lookup *)
        N.lookup table proto ((V4 ip_header.src), sport)
           ((V4 ip_header.dst), dport) >>= function
        | None ->
           Lwt.return Untranslated (* don't autocreate new entries *)
        | Some (_expiry, ((V4 new_src, new_sport), (V4 new_dst, new_dport))) ->
        (* TODO: we should probably refuse to pass TTL = 0 and instead send an
            ICMP message back to the sender *)
            match Nat_decompose.rewrite_packet ~ethernet ~network:(ip_header, ip_payload) ~transport ~src:(new_src, new_sport) ~dst:(new_dst, new_dport) with
            | Result.Ok () -> Lwt.return Translated
            | Result.Error s -> Log.warn (fun f -> f "Translating a packet failed: %s; packet content: %a" s Cstruct.hexdump_pp frame);
              Lwt.return Untranslated

  let add_entry mode table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    (* decompose this frame; if we can't, bail out now *)
    match Nat_decompose.decompose frame with
    | Result.Error s ->
      Logs.debug (fun f -> f "add_entry failing on unparseable packet, reason %s. Packet dump: %a" s Cstruct.hexdump_pp frame);
      Lwt.return Unparseable
    | Result.Ok { ethernet; network; transport } ->
      match network, Nat_decompose.ports transport with
      | Ipv6 _ , _ | Arp _, _ | Ipv4 _, None ->
        Lwt.return Unparseable (* TODO: not quite *)
      | Ipv4 (ip_header, ip_payload), Some (proto, transport, src_port, dst_port) ->
        let check_scope ip =
          match Ipaddr.scope ip with
          | Global | Organization -> true
          | _ -> false
        in
        let (src, dst) = (V4 ip_header.src), (V4 ip_header.dst) in
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
          match proto with
            | Udp -> Int64.of_int 60 (* UDP gets 60 seconds *)
            | Tcp -> Int64.of_int (60*60*24) (* TCP gets a day *)
          in
          N.insert table expiration_window proto entries >>= function
          | Some t -> Lwt.return Ok
          | None -> Lwt.return Overlap

  let add_redirect table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    add_entry Redirect table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port)

  let add_nat table frame (xl_ip, xl_port) =
    add_entry Nat table frame (xl_ip, xl_port) (xl_ip, xl_port)

end
