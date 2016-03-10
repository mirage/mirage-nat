open Ipaddr
open Mirage_nat
open Nat_decompose
open Test_lib

let assert_equal = OUnit.assert_equal

type direction = | Source | Destination

let zero_cstruct cs =
  Cstruct.memset cs 0; cs

let int_of_protocol = function
  | Udp -> 17
  | Tcp -> 6

let (>>=) = Lwt.bind

let ipv4_of_str = Ipaddr.V4.of_string_exn

module Rewriter = Mirage_nat_hashtable.Make(Unix_clock)(Unix_time)

module Constructors = struct

  let expiry = 0

  let basic_ipv4_frame ?(frame_size=1024) (proto : protocol) src dst ttl smac_addr =
    (* ethernet layer *)
    let ethernet_frame = zero_cstruct (Cstruct.create frame_size) in
    let ethernet_frame = Cstruct.set_len ethernet_frame
        (Wire_structs.sizeof_ethernet + Wire_structs.Ipv4_wire.sizeof_ipv4) in
    Wire_structs.set_ethernet_src (Macaddr.to_bytes smac_addr) 0 ethernet_frame;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x0800;

    (* ipv4 layer *)
    let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
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
    let ip_layer = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
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
    set_tcp_dataoff tcp_buf 0x50;
    set_tcp_flags tcp_buf 2; (* syn *)
    set_tcp_window tcp_buf 536; (* default_mss from tcp/window.ml *)
    (* leave checksum and urgent pointer unset *)
    (frame, len + sizeof_tcp)

  let add_udp (frame, len) source_port dest_port =
    let frame = Cstruct.set_len frame (len + Wire_structs.sizeof_udp) in
    let udp_buf = Cstruct.shift frame len in
    Wire_structs.set_udp_source_port udp_buf source_port;
    Wire_structs.set_udp_dest_port udp_buf dest_port;
    Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp);
    (* leave checksum unset *)
    (frame, len + Wire_structs.sizeof_udp)

  let full_packet ~proto ~ttl ~src ~dst ~sport ~dport =
    let smac_addr = Macaddr.of_string_exn "00:16:3e:ff:00:ff" in
    let (frame, len) =
      basic_ipv4_frame proto src dst ttl smac_addr
    in
    let frame, final_len =
      let add_transport = match proto with
      | Tcp -> add_tcp
      | Udp -> add_udp
      in
      add_transport (frame, len) sport dport
    in
    frame

  let frame_and_redirect_table direction
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
      Rewriter.empty () >>= fun t ->
      Rewriter.add_redirect t frame
          ((V4 internal_xl), internal_xl_port)
          ((V4 internal_client), internal_client_port) >>= function
      | Ok -> Lwt.return t
      | Overlap | Unparseable -> Alcotest.fail "Failed to insert test data into table structure"
    in
    table () >>= fun table -> Lwt.return (frame, table)

  let frame_and_nat_table
      ~proto ~ttl ~src ~dst ~xl ~sport ~dport ~xlport =
    let frame = full_packet ~proto ~ttl ~src ~dst ~sport ~dport in
    let table () =
      Rewriter.empty () >>= fun t ->
      Rewriter.add_nat t frame ((V4 xl), xlport) >>= function
      | Ok -> Lwt.return t
      | Overlap | Unparseable -> Alcotest.fail "Failed to insert test data into table structure"
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
  | None -> Alcotest.fail "an expected entry was missing entirely"

(* given a source IP, destination IP, protocol, and TTL,
   check to see whether the provided Ethernet frame contains an IPv4 packet
   which has those fields set. *)
let assert_ipv4_has exp_src exp_dst exp_proto exp_ttl xl_frame =
  let printer a = Ipaddr.V4.to_string (Ipaddr.V4.of_int32 a) in
  let ipv4 = Cstruct.shift xl_frame Wire_structs.sizeof_ethernet in
  let open Wire_structs.Ipv4_wire in
  (* should still be an ipv4 packet *)
  assert_equal ~printer:string_of_int 0x0800 (Wire_structs.get_ethernet_ethertype xl_frame);

  assert_equal ~printer (Ipaddr.V4.to_int32 (exp_src)) (get_ipv4_src ipv4);
  assert_equal ~printer (Ipaddr.V4.to_int32 (exp_dst)) (get_ipv4_dst ipv4);
  assert_equal ~printer:string_of_int (int_of_protocol exp_proto) (get_ipv4_proto ipv4);
  assert_equal ~printer:string_of_int exp_ttl (get_ipv4_ttl ipv4)

let assert_transport_has exp_sport exp_dport xl_frame =
  match Nat_decompose.layers xl_frame with
  | None -> Alcotest.fail "Decomposition of a frame failed"
  | Some (frame, ip, tx, payload) ->
    let (src, dst) = Nat_decompose.ports_of_transport tx in
    OUnit.assert_equal exp_sport src;
    OUnit.assert_equal exp_dport dst

let assert_payloads_match expected actual =
  match (Nat_decompose.layers expected, Nat_decompose.layers actual) with
  | Some (_, _, _, exp_payload), Some (_, _, _, actual_payload) ->
    Printf.printf "Complete packet (expected):\n";
    Cstruct.hexdump expected;
    Printf.printf "Complete packet (actual):\n";
    Cstruct.hexdump actual;
    OUnit.assert_equal ~msg:"Payload match failure" ~cmp:(fun a b -> 0 =
                                                                     Nat_decompose.compare
                                                         a b) exp_payload actual_payload
  | _, _ -> Alcotest.fail
              "At least one packet in a payload equality assertion couldn't be decomposed"

let assert_translates table direction frame =
  Rewriter.translate table frame >>= function
  | Untranslated -> Alcotest.fail "Expected translateable frame wasn't rewritten"
  | Translated -> Lwt.return_unit

let test_nat_ipv4 proto =
  let ttl = 4 in
  let open Default_values in
  Constructors.frame_and_nat_table ~proto ~ttl ~src ~dst ~xl ~sport
    ~dport ~xlport >>= fun (frame, table) ->
  assert_translates table Source frame >>= fun () ->
  Constructors.frame_and_nat_table ~proto ~ttl ~src ~dst ~xl ~sport
    ~dport ~xlport >>= fun (bare_frame, _) ->
  assert_payloads_match bare_frame frame;
  assert_ipv4_has xl dst proto (ttl - 1) frame;
  assert_transport_has xlport dport frame;
  Lwt.return_unit

let test_add_redirect_valid_pkt () =
  let proto = Udp in
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
  Constructors.frame_and_redirect_table Source ~proto ~ttl:52 
    ~outside_src:outside_requester ~external_xl:nat_external_ip
    ~outside_sport:outside_requester_port ~external_xl_port:nat_external_port
    ~internal_xl:nat_internal_ip ~internal_xl_port:nat_internal_port
    ~internal_client:internal_client ~internal_client_port:internal_client_port
  >>= fun (frame, table) ->
  assert_translates table Source frame >>= fun () ->
  let orig_frame = Constructors.full_packet ~proto ~ttl:52 ~src:outside_requester
      ~dst:nat_external_ip ~sport:outside_requester_port
      ~dport:nat_external_port
  in
  assert_payloads_match frame orig_frame;
  (* return direction frame translates too *)
  let reverse_packet =
    Constructors.full_packet ~proto ~ttl:52 ~src:internal_client
      ~sport:internal_client_port ~dst:nat_internal_ip ~dport:nat_internal_port
  in
  assert_translates table Destination reverse_packet >>= fun () ->
  let orig_reverse_packet =
    Constructors.full_packet ~proto ~ttl:52 ~src:internal_client
      ~sport:internal_client_port ~dst:nat_internal_ip ~dport:nat_internal_port
  in
  assert_payloads_match reverse_packet orig_reverse_packet;
  Rewriter.add_redirect table orig_frame
    ((Ipaddr.V4 nat_internal_ip), nat_internal_port)
    ((Ipaddr.V4 internal_client), internal_client_port) >>= function
    | Overlap -> Alcotest.fail "overlap claimed for update of entry"
    | Unparseable ->
      Printf.printf "Allegedly unparseable frame follows:\n";
      Cstruct.hexdump frame;
      Alcotest.fail "add_redirect claimed that a reference packet was unparseable"
    | Ok ->
      (* attempting to add another entry which partially overlaps should fail *)
      Rewriter.add_redirect table orig_frame
        ((Ipaddr.of_string_exn "8.8.8.8"), nat_internal_port)
        ((Ipaddr.V4 internal_client), internal_client_port) >>= function
      | Overlap -> Lwt.return_unit
      | Ok -> Alcotest.fail "overlapping entry addition allowed"
      | Unparseable ->
        Printf.printf "Allegedly unparseable frame follows:\n";
        Cstruct.hexdump frame;
        Alcotest.fail "add_redirect claimed that a reference packet was unparseable"

let test_add_nat_valid_pkt () =
  let open Default_values in
  let proto = Udp in
  let frame = Constructors.full_packet ~proto ~ttl:52 ~src ~dst ~sport ~dport in
  Rewriter.empty () >>= fun table ->
  Rewriter.add_nat table frame ((V4 xl), xlport) >>= function
  | Overlap -> Alcotest.fail "add_nat claimed overlap when inserting into an
                 empty table"
  | Unparseable ->
    Printf.printf "Allegedly unparseable frame follows:\n";
    Cstruct.hexdump frame;
    Alcotest.fail "add_nat claimed that a reference packet was unparseable"
  | Ok ->
    (* make sure table actually has the entries we expect *)
    assert_translates table Source frame >>= fun () ->
    let orig_frame = Constructors.full_packet ~proto ~ttl:52 ~src ~dst ~sport ~dport in
    assert_payloads_match frame orig_frame;
    let reverse_frame = Constructors.full_packet ~proto ~ttl:52 ~src:dst ~dst:xl
        ~sport:dport ~dport:xlport in
    assert_translates table Destination reverse_frame >>= fun () ->
    let orig_reverse_frame = Constructors.full_packet ~proto ~ttl:52 ~src:dst ~dst:xl
        ~sport:dport ~dport:xlport in
    assert_payloads_match orig_reverse_frame reverse_frame;
    (* trying the same operation again should update the expiration time *)
    Rewriter.add_nat table orig_frame ((V4 xl), xlport) >>= function
    | Overlap -> Alcotest.fail "add_nat disallowed an update"
    | Unparseable ->
      Printf.printf "Allegedly unparseable frame follows:\n";
      Cstruct.hexdump frame;
      Alcotest.fail "add_nat claimed that a reference packet was unparseable"
    | Ok ->
      (* a half-match should fail with Overlap *)
      let frame = Constructors.full_packet ~proto ~ttl:52 ~src:xl ~dst ~sport ~dport in
      Rewriter.add_nat table frame ((Ipaddr.V4 xl), xlport) >>= function
      | Ok -> Alcotest.fail "overlap wasn't detected"
      | Unparseable ->
        Printf.printf "Allegedly unparseable frame follows:\n";
        Cstruct.hexdump frame;
        Alcotest.fail "add_nat claimed that a reference packet was unparseable"
      | Overlap -> Lwt.return_unit


let test_add_nat_nonsense () =
  (* sorts of bad packets: broadcast packets,
     non-tcp/udp/icmp packets *)
  let open Default_values in
  let proto = Udp in
  let frame_size = (Wire_structs.sizeof_ethernet + Wire_structs.Ipv4_wire.sizeof_ipv4) in
  let mangled_looking, _ = Constructors.basic_ipv4_frame ~frame_size proto src dst 60 smac_addr in
  Rewriter.empty () >>= fun t ->
  Rewriter.add_nat t mangled_looking ((Ipaddr.V4 xl), xlport) >>= function
  | Rewriter.Ok -> Alcotest.fail "add_nat happily took a mangled packet"
  | Rewriter.Overlap -> Alcotest.fail
                 "add_nat claimed a mangled packet was already in the table"
  | Rewriter.Unparseable -> Lwt.return_unit

let test_add_nat_broadcast () =
  let open Default_values in
  let proto = Udp in
  let broadcast_dst = ipv4_of_str "255.255.255.255" in
  let broadcast = Constructors.full_packet ~proto:Tcp ~ttl:30 ~src
      ~dst:broadcast_dst ~sport ~dport in
  Rewriter.empty () >>= fun t ->
  Rewriter.add_nat t broadcast ((Ipaddr.V4 xl), xlport) >>= function
  | Ok | Overlap -> Alcotest.fail "add_nat operated on a broadcast packet"
  | Unparseable ->
    (* try just an ethernet frame *)
    let e = zero_cstruct (Cstruct.create Wire_structs.sizeof_ethernet) in
    Rewriter.empty () >>= fun t ->
    Rewriter.add_nat t e ((Ipaddr.V4 xl), xlport) >>= function
    | Ok | Overlap ->
      Alcotest.fail "add_nat claims to have succeeded with a bare ethernet frame"
    | Unparseable -> Lwt.return_unit

type packet_variables = {
  src : Ipaddr.V4.t;
  dst : Ipaddr.V4.t;
  ttl : Cstruct.uint8;
  sport : Cstruct.uint16;
  dport : Cstruct.uint16;
}

let add_many_entries how_many =
  let random_ttl () = (Random.int 255) + 1 in
  let rec random_ipv4 () =
    let addr = Ipaddr.V4.of_int32 (Random.int32 Int32.max_int) in
    match scope (V4 addr) with
    | Global | Organization -> addr
    | Point | Link | Interface | Site | Admin ->
      Printf.printf "unusable address %s generated; trying again\n%!" (Ipaddr.V4.to_string addr);
      random_ipv4 ()
  in
  let random_port () = Random.int 65536 in
  let random_packet () =
    let src = random_ipv4 () in
    let dst = random_ipv4 () in
    let sport = random_port () in
    let dport = random_port () in
    let ttl = random_ttl () in
    let r = { src; dst; sport; dport; ttl } in
    (Constructors.full_packet ~proto:Tcp ~ttl ~src ~dst ~sport ~dport, r)
  in
  (* test results are a little easier to reason about if we mimic the expected
     behaviour of users -- NATting stuff from gateway IP to another IP
     downstream from a gateway, both of which are fixed *)
  Random.self_init ();
  let fixed_internal_ip = random_ipv4 () in
  let fixed_external_ip = random_ipv4 () in
  Rewriter.empty () >>= fun t ->
  let rec shove_entries = function
    | n when n <= 0 -> Lwt.return_unit
    | n ->
      Printf.printf "%d more entries...\n%!" n;
      let (packet, values) = random_packet () in
      Rewriter.translate t packet >>= function
      | Translated ->
        Printf.printf "already a Source entry for the packet; trying again\n%!";
        shove_entries n (* generated an overlap; try again *)
      | Untranslated ->
        Rewriter.translate t packet >>= function 
        | Translated ->
          Printf.printf "already a Destination entry for the packet; trying again\n%!";
          shove_entries n 
        | Untranslated ->
          let add_fn =
            (* bias creation of NAT rules over redirects *)
            match (Random.int 10) with
            | 0 ->
              Printf.printf "adding a redirect rule\n%!";
              Rewriter.add_redirect t packet ((V4 fixed_external_ip), random_port ())
                ((V4 fixed_internal_ip), random_port ())
            | _ ->
              Printf.printf "adding a NAT rule\n%!";
              Rewriter.add_nat t packet ((V4 fixed_external_ip), random_port ())
          in
          add_fn >>= function
          | Unparseable ->
            let print_ip ip = Printf.sprintf "%x (%s)"
                (Int32.to_int (Ipaddr.V4.to_int32 ip))
                (Ipaddr.V4.to_string ip) in
            Printf.printf "With %d entries yet to go,
            Failure parsing this packet, which was automatically generated from
            the following values:\n" n;
            Printf.printf "source: %s, %x\n" (print_ip values.src) values.sport;
            Printf.printf "destination: %s, %x\n" (print_ip values.dst) values.dport;
            Printf.printf "ttl: %x\n" values.ttl;
            Cstruct.hexdump packet;
            Alcotest.fail "Parse failure"
          | Overlap ->
            Printf.printf "overlap between entries; trying again\n%!";
            shove_entries n
          | Ok -> shove_entries (n-1)
  in
  shove_entries how_many

let lwt_run f () = Lwt_main.run (f ())

let correct_mappings =
  [
    "IPv4 UDP NAT rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Udp) ;
    "IPv4 TCP NAT rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Tcp) ;
  ]

let add_nat = [
  "add_nat makes entries", `Quick, lwt_run test_add_nat_valid_pkt;
  "add_nat refuses nonsense frames", `Quick, lwt_run test_add_nat_nonsense;
  "add_nat refuses broadcast frames", `Quick, lwt_run test_add_nat_broadcast;
]

let add_redirect = [
    (* TODO: test add_nat in non-ipv4 contexts; add_redirect more
    fully *)
    "add_redirect makes entries", `Quick, lwt_run test_add_redirect_valid_pkt;
]

let many_entries = [
  "many entries are added successfully", `Quick, lwt_run (fun () ->
      add_many_entries 200);
]

let () = Alcotest.run "Mirage_nat.Nat_rewrite" [
    "correct_mappings", correct_mappings;
    "add_nat", add_nat;
    "add_redirect", add_redirect;
    "many_entries", many_entries;
  ]
