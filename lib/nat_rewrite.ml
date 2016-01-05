open Ipaddr
open Nat_shims (* V4 and V6 definitions *)
open Mirage_nat

type 'a layer = 'a Nat_decompose.layer
type ethernet = Nat_decompose.ethernet
type ip = Nat_decompose.ip
type transport = Nat_decompose.transport

module Make(Nat_table : Mirage_nat.Lookup) : sig
  include Mirage_nat.S with type config = Nat_table.config 
end = struct
  module N = Nat_table
  type t = N.t
  type config = Nat_table.config

  type insert_result =
    | Ok
    | Overlap
    | Unparseable

  let (>>=) = Lwt.bind

  let protofy num = match num with
    | 6 -> Some Tcp
    | 17 -> Some Udp
    | _ -> None

  let empty (config : N.config) = N.empty config

  let translate table direction frame =
    MProf.Trace.label "Nat_rewrite.translate";
    (* note that ethif.input doesn't have the same register-listeners-then-input
       format that tcp/udp do, so we could use it for the outer layer of parsing *)
    (* TODO: this is not correct for IPv6 *)
    (* TODO: it's not clear to me whether we need to do this, since most users
       will be sending packets via IP.write, which itself calculates and inserts
       the proper checksum before sending the packet. *)
    match Nat_decompose.layers frame with
    | None -> Lwt.return Untranslated (* un-NATtable packet; drop it like it's hot *)
    | Some (frame, ip_packet, higherproto_packet, _payload) ->
      match (Nat_decompose.addresses_of_ip ip_packet) with
      | (V4 src, V6 dst) -> Lwt.return Untranslated (* impossible! *)
      | (V6 src, V4 dst) -> Lwt.return Untranslated (* impossible! *)
      | (V6 src, V6 dst) -> Lwt.return Untranslated (* TODO, obviously *)
      | (V4 src, V4 dst) ->
        match protofy (Nat_decompose.proto_of_ip ip_packet) with
        | None -> Lwt.return Untranslated (* TODO: don't just drop all non-udp, non-tcp packets *)
        | Some proto ->
          let (sport, dport) = Nat_decompose.ports_of_transport higherproto_packet in
          (* got everything; do the lookup *)
          N.lookup table proto ((V4 src), sport) ((V4 dst), dport) >>= function
          | None -> Lwt.return Untranslated (* don't autocreate new entries *)
          | Some (_expiry, ((V4 new_src, new_sport), (V4 new_dst, new_dport))) ->
            (* TODO: we should probably refuse to pass TTL = 0 and instead send an
               ICMP message back to the sender *)
            let open Nat_decompose in
            rewrite_ip false ip_packet (V4 new_src, V4 new_dst);
            rewrite_port higherproto_packet (new_sport, new_dport);
            decrement_ttl ip_packet;
            recalculate_ip_checksum ip_packet higherproto_packet;
            Lwt.return Translated

          (* TODO: 4-to-6 logic *)
          | Some (_expiry, ((V6 new_src, new_sport), (V6 new_dst, new_dport))) ->
            Lwt.return Untranslated
          | Some (_expiry, ((V6 _, _), (V4 _, _))) ->
            raise (Invalid_argument "Impossible transformation in NAT
                                         table (src ipv6, dst ipv4)")
          | Some (_expiry, ((V4 _, _), (V6 _, _))) ->
            raise (Invalid_argument "Impossible transformation in NAT
                                         table (src ipv4, dst ipv6)")

  let add_entry mode table frame
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
            (* TODO: this is silly in the case of TCP *)
            match proto with
            | Udp -> Int64.of_int 60 (* UDP gets 60 seconds *)
            | Tcp -> Int64.of_int (60*60*24) (* TCP gets a day *)
          in
          N.insert table expiration_window proto entries >>= function
          | Some t -> Lwt.return Ok
          | None -> Lwt.return Overlap
        )
      | _, _, _ -> Lwt.return Unparseable

  let add_redirect table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port) =
    add_entry Redirect table frame
      (other_xl_ip, other_xl_port)
      (final_destination_ip, final_destination_port)

  let add_nat table frame (xl_ip, xl_port) =
    add_entry Nat table frame (xl_ip, xl_port) (xl_ip, xl_port)

end
