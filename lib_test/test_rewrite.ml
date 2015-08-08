open OUnit2
open Ipaddr
open Nat_rewrite
open Nat_decompose
open Test_lib

let zero_cstruct cs =
  Cstruct.memset cs 0;
  cs

type protocol = Nat_lookup.protocol
let int_of_protocol = function
  | Nat_lookup.Udp -> 17
  | Nat_lookup.Tcp -> 6

let (>>=) = Lwt.bind

let ipv4_of_str = Ipaddr.V4.of_string_exn

module R = Nat_rewrite.Make(N)

module Constructors = struct

  let expiry = 0.

  let basic_ipv4_frame ?(frame_size=1024) (proto : protocol) src dst ttl smac_addr =
    let ethernet_frame = zero_cstruct (Cstruct.create frame_size) in
    let ethernet_frame = Cstruct.set_len ethernet_frame
        (Wire_structs.sizeof_ethernet + Wire_structs.Ipv4_wire.sizeof_ipv4) in
    Wire_structs.set_ethernet_src (Macaddr.to_bytes smac_addr) 0 ethernet_frame;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x0800;
    match ip_and_above_of_frame ethernet_frame with
    | None -> OUnit.assert_failure "failure constructing test frame"
    | Some buf ->
      (* Write the constant IPv4 header fields *)
      Wire_structs.Ipv4_wire.set_ipv4_hlen_version buf ((4 lsl 4) + (5));
      Wire_structs.Ipv4_wire.set_ipv4_tos buf 0;
      Wire_structs.Ipv4_wire.set_ipv4_off buf 0;
      Wire_structs.Ipv4_wire.set_ipv4_ttl buf ttl;
      Wire_structs.Ipv4_wire.set_ipv4_proto buf (int_of_protocol proto);
      Wire_structs.Ipv4_wire.set_ipv4_src buf (Ipaddr.V4.to_int32 src); (* altered *)
      Wire_structs.Ipv4_wire.set_ipv4_dst buf (Ipaddr.V4.to_int32 dst);
      Wire_structs.Ipv4_wire.set_ipv4_id buf 0x4142;
      let len = Wire_structs.sizeof_ethernet + Wire_structs.Ipv4_wire.sizeof_ipv4 in
      (ethernet_frame, len)

  let basic_ipv6_frame proto src dst ttl smac_addr =
    let ethernet_frame = zero_cstruct (Cstruct.create
                                         (Wire_structs.sizeof_ethernet +
                                          Wire_structs.Ipv6_wire.sizeof_ipv6)) in
    let smac = Macaddr.to_bytes smac_addr in
    Wire_structs.set_ethernet_src smac 0 ethernet_frame;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd;
    match ip_and_above_of_frame ethernet_frame with
    | None -> OUnit.assert_failure "failure constructing test frame"
    | Some ip_layer ->
      Wire_structs.Ipv6_wire.set_ipv6_version_flow ip_layer 0x60000000l;
      Wire_structs.Ipv6_wire.set_ipv6_src (Ipaddr.V6.to_bytes src) 0 ip_layer;
      Wire_structs.Ipv6_wire.set_ipv6_dst (Ipaddr.V6.to_bytes dst) 0 ip_layer;
      Wire_structs.Ipv6_wire.set_ipv6_nhdr ip_layer proto;
      Wire_structs.Ipv6_wire.set_ipv6_hlim ip_layer ttl;
      let len = Wire_structs.sizeof_ethernet + Wire_structs.Ipv6_wire.sizeof_ipv6 in
      (ethernet_frame, len)

  let add_tcp (frame, len) source_port dest_port =
    let open Wire_structs.Tcp_wire in
    let frame = Cstruct.set_len frame (len + Wire_structs.Tcp_wire.sizeof_tcp) in
    let tcp_buf = Cstruct.shift frame len in
    set_tcp_src_port tcp_buf source_port;
    set_tcp_dst_port tcp_buf dest_port;
    (* for now, all tcp packets have syn set & have a consistent seq # *)
    (* they also don't have options *)
    set_tcp_sequence tcp_buf (Int32.of_int 0x432af310);
    set_tcp_ack_number tcp_buf Int32.zero;
    set_tcp_dataoff tcp_buf 5;
    set_tcp_flags tcp_buf 2; (* syn *)
    set_tcp_window tcp_buf 536; (* default_mss from tcp/window.ml *)
    (* leave checksum and urgent pointer unset *)
    (frame, len + sizeof_tcp)

  let add_udp (frame, len) source_port dest_port =
    (* also cribbed from mirage-tcpip *)
    let frame = Cstruct.set_len frame (len + Wire_structs.sizeof_udp) in
    let udp_buf = Cstruct.shift frame len in
    Wire_structs.set_udp_source_port udp_buf source_port;
    Wire_structs.set_udp_dest_port udp_buf dest_port;
    Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp);
    (* leave checksum unset *)
    (frame, len + Wire_structs.sizeof_udp)

  (* basic_tcp_frame should return a frame that needs rewriting in the supplied direction --
   * i.e., if direction = Destination, one from 4.141.2.6 (dst)
     to 128.104.108.1 (xl), which needs to have
    * 128.104.108.1 (xl) rewritten to 192.168.108.26 (src) *)

  let full_packet
      ~proto ~ttl ~src ~dst ~sport ~dport =
    let smac_addr = Macaddr.of_string_exn "00:16:3e:ff:00:ff" in
    let (frame, len) =
      basic_ipv4_frame proto src dst ttl smac_addr
    in
    let frame, _ =
      let add_transport = match proto with
      | Tcp -> add_tcp
      | Udp -> add_udp
      in
      add_transport (frame, len) sport dport
    in
    frame

  let frame_and_redirect_table (direction : Nat_rewrite.direction) 
      ~proto ~ttl 
      ~outside_src ~external_xl ~internal_xl ~internal_client
      ~outside_sport ~external_xl_port ~internal_xl_port ~internal_client_port =
    let frame = 
      match direction with
      | Source -> full_packet ~proto ~ttl
                    ~src:outside_src ~dst:external_xl
                    ~sport:outside_sport ~dport:external_xl_port
      | Destination -> full_packet ~proto ~ttl
                         ~src:internal_xl ~dst:internal_client
                         ~sport:internal_xl_port ~dport:internal_client_port
    in
    let table () =
      let mappings = Nat_translations.map_redirect
          ~left:((V4 outside_src), outside_sport)
          ~right:((V4 external_xl), external_xl_port)
          ~translate_left:((V4 internal_xl), internal_xl_port)
          ~translate_right:((V4 internal_client), internal_client_port)
      in
      N.empty () >>= fun t ->
      insert_mappings t expiry proto mappings >>= function
      | None -> assert_failure "Failed to insert test data into table structure"
      | Some t -> Lwt.return t
    in
    table () >>= fun table -> Lwt.return (frame, table)

  let frame_and_nat_table (direction : Nat_rewrite.direction)
      ~proto ~ttl ~src ~dst ~xl ~sport ~dport ~xlport =
    let frame = 
      match direction with
      | Source -> full_packet ~proto ~ttl ~src ~dst ~sport ~dport 
      | Destination ->
        full_packet ~proto ~ttl ~src:dst ~dst:xl ~sport:dport ~dport:xlport
    in
    let table () =
      let mappings = Nat_translations.map_nat
          ~left:((V4 src), sport) ~right:((V4 dst), dport) ~translate_left:((V4 xl), xlport)
      in
      N.empty () >>= fun t ->
      insert_mappings t expiry proto mappings >>= function
      | None -> assert_failure "Failed to insert test data into table structure"
      | Some t -> Lwt.return t
    in
    table () >>= fun table -> Lwt.return (frame, table)

end

module Default_values = struct
  let smac_addr = Macaddr.of_string_exn "00:16:3e:ff:00:ff"
  let src = (ipv4_of_str "192.168.108.26")
  let dst = (ipv4_of_str "4.141.2.6")
  let xl = (ipv4_of_str "128.104.108.1")
  let sport, dport, xlport = 255, 1024, 45454
end

let check_entry expected (actual : ((Ipaddr.t * int) * (Ipaddr.t * int)) option) =
  let printer (left, right) =
    Printf.sprintf "(%s, %d) -> (%s, %d)"
      (Ipaddr.to_string (fst left)) (snd left)
      (Ipaddr.to_string (fst right)) (snd right)
  in
  match actual with
  | Some a -> assert_equal ~printer expected a
  | None -> assert_failure
              "an expected entry was missing entirely"

(* given a source IP, destination IP, protocol, and TTL, 
   check to see whether the provided Ethernet frame contains an IPv4 packet
   which has those fields set. *)
let assert_ipv4_has exp_src exp_dst exp_proto exp_ttl xl_frame =
  let printer a = Ipaddr.V4.to_string (Ipaddr.V4.of_int32 a) in
  match ip_and_above_of_frame xl_frame with
  | None -> OUnit.assert_failure "tried to rewrite a messed-up frame"
  | Some ipv4 ->
    let open Wire_structs.Ipv4_wire in
    (* should still be an ipv4 packet *)
    assert_equal 0x0800 (Wire_structs.get_ethernet_ethertype xl_frame);

    assert_equal ~printer (Ipaddr.V4.to_int32 (exp_src)) (get_ipv4_src ipv4);
    assert_equal ~printer (Ipaddr.V4.to_int32 (exp_dst)) (get_ipv4_dst ipv4);
    assert_equal ~printer:string_of_int (int_of_protocol exp_proto) (get_ipv4_proto ipv4);
    assert_equal ~printer:string_of_int exp_ttl (get_ipv4_ttl ipv4)

let assert_transport_has exp_sport exp_dport xl_frame =
  match Nat_decompose.layers xl_frame with
  | None -> OUnit.assert_failure "Decomposition of a frame failed"
  | Some (frame, ip, tx, payload) ->
    let (src, dst) = Nat_decompose.ports_of_transport tx in
    OUnit.assert_equal exp_sport src;
    OUnit.assert_equal exp_dport dst

let assert_payloads_match expected actual =
  match (Nat_decompose.layers expected, Nat_decompose.layers actual) with
  | Some (_, _, _, exp_payload), Some (_, _, _, actual_payload) ->
    OUnit.assert_equal ~cmp:Cstruct.equal exp_payload actual_payload
  | _, _ -> OUnit.assert_failure
              "At least one packet in a payload equality assertion couldn't be decomposed"

let assert_translates table direction frame =
  R.translate table direction frame >>= function
  | None -> assert_failure "Expected translateable frame wasn't rewritten"
  | Some xl_frame -> Lwt.return xl_frame

let test_nat_ipv4 direction proto =
  let ttl = 4 in
  let open Default_values in
  Constructors.frame_and_nat_table direction ~proto ~ttl ~src ~dst ~xl ~sport
    ~dport ~xlport >>= fun (frame, table) ->
  assert_payloads_match frame frame;
  assert_translates table direction frame >>= fun xl_frame ->
  assert_payloads_match frame xl_frame;
  match direction with
  | Destination ->
    assert_ipv4_has dst src proto (ttl - 1) xl_frame;
    assert_transport_has dport sport xl_frame;
    Lwt.return_unit
  | Source ->
    assert_ipv4_has xl dst proto (ttl - 1) xl_frame;
    assert_transport_has xlport dport xl_frame;
    Lwt.return_unit

let test_make_redirect_entry_valid_pkt () =
  let proto = Nat_lookup.Udp in
  let internal_client = ipv4_of_str "172.16.2.30" in
  let outside_requester = ipv4_of_str "1.2.3.4" in
  let nat_external_ip = ipv4_of_str "208.121.103.4" in
  let nat_internal_ip = ipv4_of_str "172.16.2.1" in
  let internal_client_port, outside_requester_port,
      nat_external_port, nat_internal_port = 18787, 80, 80, 8989 in
  let frame = Constructors.full_packet ~proto ~ttl:52 ~src:outside_requester
      ~dst:nat_external_ip ~sport:outside_requester_port
      ~dport:nat_external_port
  in
  N.empty () >>= fun table ->
  R.make_redirect_entry table frame
          ((Ipaddr.V4 nat_internal_ip), nat_internal_port)
          ((Ipaddr.V4 internal_client), internal_client_port) >>= function
  | Overlap -> assert_failure "make_redirect_entry claimed overlap when inserting into an
                 empty table"
  | Unparseable ->
    Printf.printf "Allegedly unparseable frame follows:\n";
    Cstruct.hexdump frame;
    assert_failure "make_redirect_entry claimed that a reference packet was unparseable"
  | Ok t ->
    (* make sure table actually has the entries we expect *)
    N.lookup t proto (V4 internal_client, internal_client_port)
        (V4 nat_internal_ip, nat_internal_port) >>= fun internal_client_lookup ->
    N.lookup t proto
        (V4 outside_requester, outside_requester_port)
        (V4 nat_external_ip, nat_external_port) >>= fun outside_requester_lookup ->
    check_entry
      (((V4 nat_external_ip), nat_external_port),
       ((V4 outside_requester), outside_requester_port)) internal_client_lookup;
    check_entry
      (((V4 nat_internal_ip), nat_internal_port),
       ((V4 internal_client), internal_client_port)) outside_requester_lookup;
    (* trying the same operation again should give us an Overlap failure *)
    R.make_redirect_entry table frame
            ((Ipaddr.V4 nat_internal_ip), nat_internal_port)
            ((Ipaddr.V4 internal_client), internal_client_port) >>= function
    | Overlap -> Lwt.return_unit
    | Unparseable ->
      Printf.printf "Allegedly unparseable frame follows:\n";
      Cstruct.hexdump frame;
      assert_failure "make_redirect_entry claimed that a reference packet was unparseable"
    | Ok t -> assert_failure "make_redirect_entry allowed a duplicate entry"

let test_make_nat_entry_valid_pkt () =
  let open Default_values in
  let proto = Nat_lookup.Udp in
  let frame = Constructors.full_packet ~proto ~ttl:52 ~src ~dst ~sport ~dport in
  N.empty () >>= fun table ->
  R.make_nat_entry table frame (Ipaddr.V4 xl) xlport >>= function
  | Overlap -> assert_failure "make_nat_entry claimed overlap when inserting into an
                 empty table"
  | Unparseable ->
    Printf.printf "Allegedly unparseable frame follows:\n";
    Cstruct.hexdump frame;
    assert_failure "make_nat_entry claimed that a reference packet was unparseable"
  | Ok t ->
    (* make sure table actually has the entries we expect *)
    N.lookup t proto (V4 src, sport) (V4 dst, dport) >>= fun src_lookup ->
    N.lookup t proto (V4 dst, dport) (V4 xl, xlport) >>= fun dst_lookup ->
    check_entry (((V4 xl), xlport), ((V4 dst), dport)) src_lookup;
    check_entry (((V4 dst), dport), ((V4 src), sport)) dst_lookup;
    (* trying the same operation again should give us an Overlap failure *)
    R.make_nat_entry t frame (Ipaddr.V4 xl) xlport >>= function
    | Overlap -> Lwt.return_unit
    | Unparseable ->
      Printf.printf "Allegedly unparseable frame follows:\n";
      Cstruct.hexdump frame;
      assert_failure "make_nat_entry claimed that a reference packet was unparseable"
    | Ok t -> assert_failure "make_nat_entry allowed a duplicate entry"

let test_make_nat_entry_nonsense () =
  (* sorts of bad packets: broadcast packets,
     non-tcp/udp/icmp packets *)
  let open Default_values in
  let proto = Nat_lookup.Udp in
  let frame_size = (Wire_structs.sizeof_ethernet + Wire_structs.Ipv4_wire.sizeof_ipv4) in
  let mangled_looking, _ = Constructors.basic_ipv4_frame ~frame_size proto src dst 60 smac_addr in
  N.empty () >>= fun table ->
  R.make_nat_entry table mangled_looking (Ipaddr.V4 xl) xlport >>= function
  | Ok t -> assert_failure "make_nat_entry happily took a mangled packet"
  | Overlap -> assert_failure
                 "make_nat_entry claimed a mangled packet was already in the table"
  | Unparseable -> Lwt.return_unit

let test_make_nat_entry_broadcast () =
  let open Default_values in
  let proto = Nat_lookup.Udp in
  let broadcast_dst = ipv4_of_str "255.255.255.255" in
  let broadcast = Constructors.full_packet ~proto:Tcp ~ttl:30 ~src
      ~dst:broadcast_dst ~sport ~dport in
  N.empty () >>= fun table ->
  R.make_nat_entry table broadcast (Ipaddr.V4 xl)
    xlport >>= function
  | Ok _ | Overlap -> assert_failure "make_nat_entry operated on a broadcast packet"
  | Unparseable ->
    (* try just an ethernet frame *)
    let e = zero_cstruct (Cstruct.create Wire_structs.sizeof_ethernet) in
    N.empty () >>= fun t ->
    R.make_nat_entry t e (Ipaddr.V4 xl) xlport >>= function
    | Ok _ | Overlap ->
      assert_failure "make_nat_entry claims to have succeeded with a bare ethernet frame"
    | Unparseable -> Lwt.return_unit

let lwt_run f () = Lwt_main.run (f ())

let correct_mappings = [
  "IPv4 TCP NAT source rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Source Udp) ;
  "IPv4 UDP NAT source rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Source Tcp) ;
  "IPv4 TCP NAT destination rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Destination Udp) ;
  "IPv4 UDP NAT destination rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Destination Tcp) ;
]

let make_nat_entry = [
  "make_nat_entry makes entries", `Quick, lwt_run test_make_nat_entry_valid_pkt;
  "make_nat_entry refuses nonsense frames", `Quick, lwt_run test_make_nat_entry_nonsense;
  "make_nat_entry refuses broadcast frames", `Quick, lwt_run test_make_nat_entry_broadcast;
]

let make_redirect_entry = [
    (* TODO: test make_nat_entry in non-ipv4 contexts; make_redirect_entry more
    fully *)
    "make_redirect_entry makes entries", `Quick, lwt_run test_make_redirect_entry_valid_pkt;
  ]

let () = Alcotest.run "Mirage_nat.Nat_rewrite" [
    "correct_mappings", correct_mappings;
    "make_nat_entry", make_nat_entry;
    "make_redirect_entry", make_redirect_entry;
  ]
