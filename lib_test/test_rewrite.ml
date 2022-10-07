let ipv4_of_str = Ipaddr.V4.of_string_exn

let packet_t = (module Nat_packet : Alcotest.TESTABLE with type t = Nat_packet.t)
let translate_result = Alcotest.result packet_t (Alcotest.of_pp Mirage_nat.pp_error)
let add_result = Alcotest.(result unit (of_pp Mirage_nat.pp_error))

module Rewriter = Mirage_nat_lru

module Default_values = struct
  let src = (ipv4_of_str "192.168.108.26")
  let dst = (ipv4_of_str "4.141.2.6")
  let xl = (ipv4_of_str "128.104.108.1")
  let src_port, dst_port, xlport = 255, 1024, 45454
  let payload = Cstruct.of_string "adorable_cat_photo.jpg"
end

module Constructors = struct
  let assert_checksum_correct raw =
    Format.printf "Check %a@." Cstruct.hexdump_pp raw;
    match Ipv4_packet.Unmarshal.of_cstruct raw with
    | Error e -> Alcotest.fail (Fmt.str "assert_checksum failed: %s" e)
    | Ok (ipv4_header, transport_packet) ->
      Printf.printf "ipv4_header len = %d\n" (Cstruct.length raw - Cstruct.length transport_packet);
      let proto =
        match Ipv4_packet.(Unmarshal.int_to_protocol ipv4_header.proto) with
        | Some (`TCP | `UDP as p) -> p
        | _ -> assert false
      in
      Alcotest.(check bool) "Transport checksum correct" true
        (Ipv4_packet.Unmarshal.verify_transport_checksum ~ipv4_header ~transport_packet ~proto)

  let check_save_restore packet =
    let cache = Fragments.Cache.empty 10 in
    let raw_to_cstruct =
      match Nat_packet.to_cstruct packet with
      | Ok [ data ] -> data
      | _ -> Alcotest.fail "to_cstruct resulted in more fragments";
    in
    let raw_into_cstruct =
      let buf = Cstruct.create 2048 in
      match Nat_packet.into_cstruct packet buf with
      | Error e -> Alcotest.fail (Fmt.str "into_cstruct failed: %a" Nat_packet.pp_error e)
      | Ok (n, []) -> Cstruct.sub buf 0 n
      | Ok (_, _) -> Alcotest.fail (Fmt.str "into_cstruct resulted in more fragments")
    in
    assert_checksum_correct raw_to_cstruct;
    assert_checksum_correct raw_into_cstruct;
    let check_packet raw =
      match snd (Nat_packet.of_ipv4_packet cache ~now:0L raw) with
      | Ok Some loaded when Nat_packet.equal packet loaded -> ()
      | Ok Some loaded -> Alcotest.fail (Fmt.str "Packet changed by save/load! Saved:@.%a@.Got:@.%a"
                                           Nat_packet.pp packet
                                           Nat_packet.pp loaded
                                           )
      | Ok None -> Alcotest.fail (Fmt.str "Packet changed by save/load! Saved:@.%a@.Got nothing"
                                    Nat_packet.pp packet)
      | Error e   -> Alcotest.fail (Fmt.str "Failed to load saved packet! Saved:@.%a@.As:@.%a@.Error: %a"
                                      Nat_packet.pp packet
                                      Cstruct.hexdump_pp raw
                                      Nat_packet.pp_error e
                                   )
    in
    check_packet raw_to_cstruct;
    check_packet raw_into_cstruct

  let full_packet ~payload ~proto ~ttl ~src ~dst ~src_port ~dst_port =
    let transport = match proto with
    | `UDP -> `UDP ({Udp_packet.src_port = src_port; dst_port = dst_port}, payload)
    | `TCP -> `TCP (
        {Tcp.Tcp_packet.src_port = src_port; dst_port = dst_port;
         sequence = Tcp.Sequence.of_int 0x432af310;
         ack_number = Tcp.Sequence.zero;
         urg = false; ack = false; psh = false; rst = false; syn = true; fin = false;
         window = 536;
         options = []; (* If this is changed, need to change the length sent to `pseudoheader` above *)
        }, payload)
    in
    let proto = Ipv4_packet.Marshal.protocol_to_int (proto :> Ipv4_packet.protocol) in
    let ip = { Ipv4_packet.src; dst; proto; ttl; id=0x00; off = 0; options = (Cstruct.create 0) } in
    let packet = `IPv4 (ip, transport) in
    check_save_restore packet;
    packet

  let make_table_with_redirect ip_packet ~internal_xl ~internal_xl_port_gen ~internal_client ~internal_client_port =
    let t = Rewriter.empty ~tcp_size:10 ~udp_size:10 ~icmp_size:10 in
    match
      Rewriter.add t ip_packet
        internal_xl internal_xl_port_gen
        (`Redirect (internal_client, internal_client_port))
    with
    | Error e -> Alcotest.fail (Fmt.str "Failed to insert test data into table structure: %a" Mirage_nat.pp_error e)
    | Ok () -> t

  let make_table_with_nat ip_packet ~xl ~xlport_gen =
    let t = Rewriter.empty ~tcp_size:10 ~udp_size:10 ~icmp_size:10 in
    match Rewriter.add t  ip_packet xl xlport_gen `NAT with
    | Error e ->
      Alcotest.fail (Fmt.str "Failed to insert test data into table structure: %a" Mirage_nat.pp_error e)
    | Ok () -> t

  let make_icmp ~src ~dst ~ttl icmp =
    let src = Ipaddr.V4.of_string_exn src in
    let dst = Ipaddr.V4.of_string_exn dst in
    let proto = Ipv4_packet.Marshal.protocol_to_int `ICMP in
    let icmp, payload =
      match icmp with
      | `Echo_request (id, seq, payload) -> {
          Icmpv4_packet.ty = Icmpv4_wire.Echo_request;
          code = 0;
          subheader = Icmpv4_packet.Id_and_seq (id, seq)
        }, payload
      | `Echo_reply (id, seq, payload) -> {
          Icmpv4_packet.ty = Icmpv4_wire.Echo_reply;
          code = 0;
          subheader = Icmpv4_packet.Id_and_seq (id, seq)
        }, payload
      | `Unreachable err ->
        {
          Icmpv4_packet.ty = Icmpv4_wire.Destination_unreachable;
          code = 1;
          subheader = Icmpv4_packet.Unused;
        }, err
    in
    let ip = {Ipv4_packet.src; dst; ttl; options = Cstruct.create 0; proto; id=0x00; off=0;} in
    `IPv4 (ip, `ICMP (icmp, payload))

end

let test_nat_ipv4 proto () =
  let ttl = 4 in
  let open Default_values in
  let packet_private =
    Constructors.full_packet ~payload:Default_values.payload ~proto ~ttl ~src ~dst ~src_port ~dst_port in
  let expected_packet =
    Constructors.full_packet ~payload:Default_values.payload ~proto ~ttl:(pred ttl) ~src:xl ~dst ~src_port:xlport ~dst_port in
  let table = Constructors.make_table_with_nat packet_private ~xl ~xlport_gen:(fun () -> xlport) in
  let r = Rewriter.translate table packet_private in
  Alcotest.check translate_result "Simple NAT" (Ok expected_packet) r

let test_add_redirect_valid_pkt () =
  let proto = `UDP in
  let internal_client = ipv4_of_str "172.16.2.30" in
  let outside_requester = ipv4_of_str "1.2.3.4" in
  let nat_external_ip = ipv4_of_str "208.121.103.4" in
  let nat_internal_ip = ipv4_of_str "172.16.2.1" in
  let internal_client_port, outside_requester_port,
      nat_external_port, nat_internal_port = 18787, 80, 80, 8989 in
  let packet =
    Constructors.full_packet ~proto ~ttl:52
      ~src:outside_requester
      ~src_port:outside_requester_port
      ~payload:Default_values.payload
      ~dst:nat_external_ip
      ~dst_port:nat_external_port
  in
  let expected_packet =
    Constructors.full_packet ~proto ~ttl:51
      ~src:nat_internal_ip
      ~src_port:nat_internal_port
      ~payload:Default_values.payload
      ~dst:internal_client
      ~dst_port:internal_client_port
  in
  let table =
    Constructors.make_table_with_redirect packet
      ~internal_xl:nat_internal_ip ~internal_xl_port_gen:(fun () -> nat_internal_port)
      ~internal_client:internal_client ~internal_client_port:internal_client_port
  in
  let r = Rewriter.translate table packet in
  Alcotest.check translate_result "Redirect" (Ok expected_packet) r;
  (* return direction packet translates too *)
  let reverse_packet =
    Constructors.full_packet ~proto ~ttl:52 ~src:internal_client
      ~src_port:internal_client_port ~dst:nat_internal_ip ~dst_port:nat_internal_port
      ~payload:Default_values.payload
  in
  let expected_packet =
    Constructors.full_packet ~proto ~ttl:51
      ~src:nat_external_ip
      ~src_port:nat_external_port
      ~payload:Default_values.payload
      ~dst:outside_requester
      ~dst_port:outside_requester_port
  in
  let r = Rewriter.translate table reverse_packet in
  Alcotest.check translate_result "Redirect reply" (Ok expected_packet) r;
  (* check errors *)
  let r =
    Rewriter.add table packet
      nat_internal_ip (fun () -> nat_internal_port)
      (`Redirect (internal_client, internal_client_port))
  in
  Alcotest.check add_result "First redirect OK" (Ok ()) r;
  (* attempting to add another entry which partially overlaps should fail *)
  let r =
    Rewriter.add  table packet
      (Ipaddr.V4.of_string_exn "8.8.8.8") (fun () -> nat_internal_port)
      (`Redirect (internal_client, internal_client_port))
  in
  Alcotest.check add_result "Overlapping redirect" (Error `Overlap) r

let test_add_nat_valid_pkt () =
  let open Default_values in
  let proto = `UDP in
  let payload = Cstruct.of_string "GET / HTTP/1.1\r\n" in
  let packet = Constructors.full_packet ~payload ~proto ~ttl:52 ~src ~dst ~src_port ~dst_port in
  let table = Constructors.make_table_with_nat packet ~xl ~xlport_gen:(fun () -> xlport) in
  (* make sure table actually has the entries we expect *)
  let expected_packet =
    Constructors.full_packet ~payload ~proto ~ttl:51 ~src:xl ~dst ~src_port:xlport ~dst_port in
  let r = Rewriter.translate table packet in
  Alcotest.check translate_result "Check NAT request" (Ok expected_packet) r;
  (* check reply *)
  let reverse_packet = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:dst ~dst:xl
      ~src_port:dst_port ~dst_port:xlport in
  let expected_reply = Constructors.full_packet ~payload ~proto ~ttl:51 ~src:dst ~dst:src
      ~src_port:dst_port ~dst_port:src_port in
  let r = Rewriter.translate table reverse_packet in
  Alcotest.check translate_result "Check NAT reply" (Ok expected_reply) r;
  (* trying the same operation again should update the expiration time *)
  let r = Rewriter.add table packet xl (fun () -> xlport) `NAT in
  Alcotest.check add_result "Check update expiration" (Ok ()) r;
  (* a half-match should fail with Overlap *)
  let packet = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:xl ~dst ~src_port ~dst_port in
  let r = Rewriter.add table packet xl (fun () -> xlport) `NAT in
  Alcotest.check add_result "Check overlap detection" (Error `Overlap) r

let test_add_nat_broadcast () =
  let cache = Fragments.Cache.empty 10 in
  let open Default_values in
  let broadcast_dst = ipv4_of_str "255.255.255.255" in
  let broadcast = Constructors.full_packet ~payload ~proto:`TCP ~ttl:30 ~src
                    ~dst:broadcast_dst ~src_port ~dst_port in
  let open Rewriter in
  let t = Rewriter.empty ~tcp_size:10 ~udp_size:10 ~icmp_size:10 in
  let r = add t broadcast xl (fun () -> xlport) `NAT in
  Alcotest.check add_result "Ignore broadcast" (Error `Cannot_NAT) r;
  (* try just an ethernet frame *)
  let e = Cstruct.create Ethernet.Packet.sizeof_ethernet in
  let r = Nat_packet.of_ethernet_frame cache ~now:0L e |> snd in
  let r = match r with Ok _ as a -> a | Error _ -> Error () in
  Alcotest.(check (result (option packet_t) unit)) "Bare ethernet frame" (Error ()) r

let add_many_entries how_many =
  let random_ttl () = (Random.int 255) + 1 in
  let rec random_ipv4 () =
    let addr = Ipaddr.V4.of_int32 (Random.int32 Int32.max_int) in
    match Ipaddr.scope (V4 addr) with
    | Global | Organization -> addr
    | Point | Link | Interface | Site | Admin ->
      Printf.printf "unusable address %s generated; trying again\n%!" (Ipaddr.V4.to_string addr);
      random_ipv4 ()
  in
  let random_port () = Random.int 65536 in
  let random_packet () =
    let src = random_ipv4 () in
    let dst = random_ipv4 () in
    let src_port = random_port () in
    let dst_port = random_port () in
    let ttl = random_ttl () in
    Constructors.full_packet ~payload:Default_values.payload ~proto:`TCP ~ttl ~src ~dst ~src_port ~dst_port
  in
  (* test results are a little easier to reason about if we mimic the expected
     behaviour of users -- NATting stuff from gateway IP to another IP
     downstream from a gateway, both of which are fixed *)
  Random.self_init ();
  let fixed_internal_ip = random_ipv4 () in
  let fixed_external_ip = random_ipv4 () in
  let open Rewriter in
  let t = empty ~tcp_size:how_many ~udp_size:how_many ~icmp_size:how_many in
  let rec shove_entries = function
    | n when n <= 0 -> t
    | n ->
      Printf.printf "%d more entries...\n%!" n;
      let packet = random_packet () in
      match translate t packet with
      | Ok _ ->
        Printf.printf "already a Source entry for the packet; trying again\n%!";
        shove_entries n (* generated an overlap; try again *)
      | Error `TTL_exceeded -> Alcotest.fail "TTL exceeded!"
      | Error `Untranslated ->
        (* bias creation of NAT rules over redirects *)
        let r =
          match (Random.int 10) with
          | 0 ->
            Printf.printf "adding a redirect rule\n%!";
            Rewriter.add  t packet fixed_external_ip random_port
              (`Redirect (fixed_internal_ip, random_port ()))
          | _ ->
            Printf.printf "adding a NAT rule\n%!";
            Rewriter.add t packet fixed_external_ip random_port `NAT
        in
        match r with
        | Error `Cannot_NAT ->
          Format.printf "With %d entries yet to go, \
                         Failure translating this packet: %a" n Nat_packet.pp packet;
          Alcotest.fail "Parse failure"
        | Error `Overlap ->
          Printf.printf "overlap between entries; trying again\n%!";
          shove_entries n
        | Ok () -> shove_entries (n-1)
  in
  shove_entries how_many

let add_and_remove_many_entries how_many =
  let gc_settings = Gc.get () in
  Gc.set { gc_settings with Gc.stack_limit = 256 };
  let fake_ip = Ipaddr.V4.localhost in
  let t = add_many_entries how_many in
  let _ = Rewriter.remove_connections t fake_ip in
  Gc.set gc_settings;
  Lwt.return_unit

let test_ping () =
  let t = Rewriter.empty ~tcp_size:10 ~udp_size:10 ~icmp_size:10 in
  let payload = Cstruct.create 0 in
  let packet = Constructors.make_icmp ~src:"192.168.1.5" ~dst:"8.8.8.8" (`Echo_request (5, 9, payload)) ~ttl:64 in
  (* Add rule *)
  let r = Rewriter.add t packet (Ipaddr.V4.of_string_exn "82.1.1.8") (fun () -> 81) `NAT in
  Alcotest.check add_result "Add ICMP rule" (Ok ()) r;
  (* Translate outgoing request *)
  let expected = Constructors.make_icmp ~src:"82.1.1.8" ~dst:"8.8.8.8" (`Echo_request (81, 9, payload)) ~ttl:63 in
  let r = Rewriter.translate t packet in
  Alcotest.check translate_result "Apply ICMP rule" (Ok expected) r;
  (* Translate reply *)
  let packet = Constructors.make_icmp ~dst:"82.1.1.8" ~src:"8.8.8.8" (`Echo_reply (81, 9, payload)) ~ttl:64 in
  let expected = Constructors.make_icmp ~dst:"192.168.1.5" ~src:"8.8.8.8" (`Echo_reply (5, 9, payload)) ~ttl:63 in
  let r = Rewriter.translate t packet in
  Alcotest.check translate_result "Map ICMP reply" (Ok expected) r

let icmp_error_payload packet =
  match Nat_packet.to_cstruct packet with
  | Ok [ raw ] ->
    begin match Ipv4_packet.Unmarshal.of_cstruct raw with
      | Error e -> Alcotest.fail e
      | Ok (ip, full_transport) ->
        let trunc_transport = Cstruct.sub full_transport 0 8 in
        let payload_len = Cstruct.length full_transport in
        Cstruct.concat [Ipv4_packet.Marshal.make_cstruct ~payload_len ip; trunc_transport]
    end
  | _ -> Alcotest.fail "to_cstruct returned error or multiple fragments"

let dec_ttl (`IPv4 (ip, transport)) =
  let ip = Ipv4_packet.{ip with ttl = ip.ttl - 1} in
  `IPv4 (ip, transport)

let test_ping_icmp_error () =
  let t = Rewriter.empty ~tcp_size:10 ~udp_size:10 ~icmp_size:10 in
  let payload = Cstruct.create 0 in
  let packet = Constructors.make_icmp ~src:"192.168.1.5" ~dst:"8.8.8.8" (`Echo_request (5, 9, payload)) ~ttl:64 in
  let nat_ip = Ipaddr.V4.of_string_exn "82.1.1.8" in
  (* Add rule *)
  let r = Rewriter.add t packet nat_ip (fun () -> 81) `NAT in
  Alcotest.check add_result "Add ICMP rule" (Ok ()) r;
  (* Translate outgoing request *)
  let expected = Constructors.make_icmp ~src:"82.1.1.8" ~dst:"8.8.8.8" (`Echo_request (81, 9, payload)) ~ttl:63 in
  let r = Rewriter.translate t packet in
  Alcotest.check translate_result "Apply NAT rule" (Ok expected) r;
  (* Translate reply *)
  let error_reply_ext = (* ICMP error from an intermediate router to NAT *)
    let error = `Unreachable (icmp_error_payload expected) in
    Constructors.make_icmp ~dst:"82.1.1.8" ~src:"8.8.8.1" error ~ttl:64 in
  let error_reply_int = (* ICMP error from intermediate router to internal machine *)
    let error = `Unreachable (icmp_error_payload (dec_ttl packet)) in
    Constructors.make_icmp ~dst:"192.168.1.5" ~src:"8.8.8.1" error ~ttl:63 in
  let r = Rewriter.translate t error_reply_ext in
  Alcotest.check translate_result "Map ICMP (ICMP error)" (Ok error_reply_int) r

let test_udp_icmp_error () =
  let replace_udp_checksum ~new_checksum
      (`IPv4 (_, (`ICMP (_, icmp_internal_payload)))) =
    let transport_header = Cstruct.shift icmp_internal_payload
        (((Ipv4_wire.get_ipv4_hlen_version icmp_internal_payload) land 0x0f) * 4)
    in
    Udp_wire.set_udp_checksum transport_header new_checksum;
  in
  let t = Rewriter.empty ~tcp_size:10 ~udp_size:10 ~icmp_size:10 in
  let payload = Cstruct.create 0 in
  let packet = Constructors.full_packet (* UDP packet to port 80 from internal machine *)
      ~payload
      ~proto:`UDP
      ~src:(Ipaddr.V4.of_string_exn "192.168.1.5")
      ~dst:(Ipaddr.V4.of_string_exn "8.8.8.8")
      ~src_port:3210
      ~dst_port:80
      ~ttl:64 in
  let nat_ip = Ipaddr.V4.of_string_exn "82.1.1.8" in
  (* Add rule *)
  let r = Rewriter.add t packet nat_ip (fun () -> 81) `NAT in
  Alcotest.check add_result "Add UDP rule" (Ok ()) r;
  (* Translate outgoing request *)
  let expected = Constructors.full_packet       (* UDP packet to port 80 from NAT *)
      ~payload
      ~proto:`UDP
      ~src:(Ipaddr.V4.of_string_exn "82.1.1.8")
      ~dst:(Ipaddr.V4.of_string_exn "8.8.8.8")
      ~src_port:81
      ~dst_port:80
      ~ttl:63 in
  let r = Rewriter.translate t packet in
  Alcotest.check translate_result "Apply NAT rule" (Ok expected) r;
  (* Translate reply *)
  let error_reply_ext = (* ICMP error from an intermediate router to NAT *)
    let error = `Unreachable (icmp_error_payload expected) in
    Constructors.make_icmp ~dst:"82.1.1.8" ~src:"8.8.8.1" error ~ttl:64 in
  (* ICMP error from intermediate router to internal machine *)
  let error_reply_int =
    let error = `Unreachable (icmp_error_payload (dec_ttl packet)) in
    Constructors.make_icmp ~dst:"192.168.1.5" ~src:"8.8.8.1" error ~ttl:63 in
  replace_udp_checksum ~new_checksum:0x9c24 error_reply_int;
  let r = Rewriter.translate t error_reply_ext in
  Alcotest.check translate_result "Map UDP (ICMP error)" (Ok error_reply_int) r

let test_tcp_icmp_error () =
  let t = Rewriter.empty ~tcp_size:10 ~udp_size:10 ~icmp_size:10 in
  let payload = Cstruct.create 1000 in
  let packet = Constructors.full_packet (* TCP packet to port 80 from internal machine *)
      ~payload
      ~proto:`TCP
      ~src:(Ipaddr.V4.of_string_exn "192.168.1.5")
      ~dst:(Ipaddr.V4.of_string_exn "8.8.8.8")
      ~src_port:3210
      ~dst_port:80
      ~ttl:64 in
  let nat_ip = Ipaddr.V4.of_string_exn "82.1.1.8" in
  (* Add rule *)
  let r = Rewriter.add t packet nat_ip (fun () -> 81) `NAT in
  Alcotest.check add_result "Add TCP rule" (Ok ()) r;
  (* Translate outgoing request *)
  let expected = Constructors.full_packet       (* TCP packet to port 80 from NAT *)
      ~payload
      ~proto:`TCP
      ~src:(Ipaddr.V4.of_string_exn "82.1.1.8")
      ~dst:(Ipaddr.V4.of_string_exn "8.8.8.8")
      ~src_port:81
      ~dst_port:80
      ~ttl:63 in
  let r = Rewriter.translate t packet in
  Alcotest.check translate_result "Apply NAT rule" (Ok expected) r;
  (* Translate reply *)
  let error_reply_ext = (* ICMP error from web-server to NAT *)
    let error = `Unreachable (icmp_error_payload expected) in
    Constructors.make_icmp ~dst:"82.1.1.8" ~src:"8.8.8.8" error ~ttl:64 in
  let error_reply_int = (* ICMP error from web-server to internal machine *)
    let error = `Unreachable (icmp_error_payload (dec_ttl packet)) in
    Constructors.make_icmp ~dst:"192.168.1.5" ~src:"8.8.8.8" error ~ttl:63 in
  let r = Rewriter.translate t error_reply_ext in
  Alcotest.check translate_result "Map TCP (ICMP error)" (Ok error_reply_int) r

let gen_icmp size =
  let data = Cstruct.create size
  and src, dst = "1.1.1.1", "2.2.2.2"
  and ttl = 64
  in
  let icmp = `Echo_request (5, 9, data) in
  Constructors.make_icmp ~src ~dst icmp ~ttl

let check_off data v =
  Alcotest.(check int __LOC__ v (Cstruct.BE.get_uint16 data 6))

let test_to_cstruct_fragmentation_simple () =
  let packet = gen_icmp 1472 in
  match Nat_packet.to_cstruct ~mtu:1500 packet with
  | Ok [ data ] ->
    Alcotest.(check int __LOC__ 1500 (Cstruct.length data));
    check_off data 0x0000
  | _ -> Alcotest.fail "expected to_cstruct to succeed"

let test_to_cstruct_fragmentation_basic () =
  let packet = gen_icmp 1500 in
  match Nat_packet.to_cstruct ~mtu:1500 packet with
  | Ok [ hd ; tl ] ->
    Alcotest.(check int __LOC__ 1500 (Cstruct.length hd));
    check_off hd 0x2000;
    Alcotest.(check int __LOC__ 48 (Cstruct.length tl));
    check_off tl 0x00B9
  | _ -> Alcotest.fail "expected to_cstruct to succeed"

let test_to_cstruct_fragmentation_three_full () =
  let packet = gen_icmp 4432 in
  match Nat_packet.to_cstruct ~mtu:1500 packet with
  | Ok [ init; more; more' ] ->
    Alcotest.(check int __LOC__ 1500 (Cstruct.length init));
    Alcotest.(check int __LOC__ 1500 (Cstruct.length more));
    Alcotest.(check int __LOC__ 1500 (Cstruct.length more'));
    check_off init 0x2000;
    check_off more 0x20B9;
    check_off more' 0x0172
  | _ -> Alcotest.fail "expected to_cstruct to succeed"

let test_to_cstruct_fragmentation_error () =
  (* puts don't fragment into IP header *)
  let `IPv4 (ip, data) = gen_icmp 1473 in
  let ip' = { ip with off = 0x4000 } in
  let packet = `IPv4 (ip', data) in
  match Nat_packet.to_cstruct ~mtu:1500 packet with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "expected to_cstruct to fail"

let test_into_cstruct_fragmentation_simple () =
  let packet = gen_icmp 1472 in
  let cs = Cstruct.create 1500 in
  match Nat_packet.into_cstruct packet cs with
  | Ok (1500, []) -> check_off cs 0x0000
  | _ -> Alcotest.fail "expected into_cstruct to succeed"

let test_into_cstruct_fragmentation_basic () =
  let packet = gen_icmp 1500 in
  let cs = Cstruct.create 1500 in
  match Nat_packet.into_cstruct packet cs with
  | Ok (1500, [ tl ]) ->
    check_off cs 0x2000;
    Alcotest.(check int __LOC__ 48 (Cstruct.length tl));
    check_off tl 0x00B9
  | _ -> Alcotest.fail "expected into_cstruct to succeed"

let test_into_cstruct_fragmentation_three_full () =
  let packet = gen_icmp 4432 in
  let cs = Cstruct.create 1500 in
  match Nat_packet.into_cstruct packet cs with
  | Ok (1500, [ more; more' ]) ->
    check_off cs 0x2000;
    check_off more 0x20B9;
    check_off more' 0x0172
  | _ -> Alcotest.fail "expected into_cstruct to succeed"

let test_into_cstruct_fragmentation_error () =
  (* puts don't fragment into IP header *)
  let `IPv4 (ip, data) = gen_icmp 1473 in
  let ip' = { ip with off = 0x4000 } in
  let packet = `IPv4 (ip', data) in
  let cs = Cstruct.create 1500 in
  match Nat_packet.into_cstruct packet cs with
  | Error _ -> ()
  | Ok _ -> Alcotest.fail "expected into_cstruct to fail"

let test_of_ipv4_packet_reassembly_basic () =
  (* extensive reassembly tests (positive, negative, out-of-order, ...) are
     in mirage-tcpip, here we just test basic operation *)
  let packet = gen_icmp 1473 in
  match Nat_packet.to_cstruct ~mtu:1500 packet with
  | Ok [ init; more ] ->
    let cache = Fragments.Cache.empty (128 * 1024)
    and now = 0L
    in
    begin match Nat_packet.of_ipv4_packet cache ~now init with
      | cache', Ok None ->
        begin match snd (Nat_packet.of_ipv4_packet cache' ~now more) with
          | Ok Some pkt -> Alcotest.check packet_t __LOC__ packet pkt
          | _ -> Alcotest.fail "expecting a packet"
        end
      | _ -> Alcotest.fail "expecting no packet"
    end
  | _ -> Alcotest.fail "to_cstruct failed"

let correct_mappings = [
  "IPv4 UDP NAT rewrites", `Quick, test_nat_ipv4 `UDP ;
  "IPv4 TCP NAT rewrites", `Quick, test_nat_ipv4 `TCP ;
]

let add_nat = [
  "add_nat makes entries",            `Quick, test_add_nat_valid_pkt;
  "add_nat refuses broadcast frames", `Quick, test_add_nat_broadcast;
  "add_nat for ping",                 `Quick, test_ping;
  "add_nat for ping ICMP error",      `Quick, test_ping_icmp_error;
  "add_nat for ICMP error with UDP",  `Quick, test_udp_icmp_error;
  "add_nat for ICMP error with TCP",  `Quick, test_tcp_icmp_error;
]

let add_redirect = [
    (* TODO: test add_nat in non-ipv4 contexts; add_redirect more fully *)
    "add_redirect makes entries", `Quick, test_add_redirect_valid_pkt;
]

let many_entries = [
  "many entries are added successfully", `Quick,
  (fun () -> ignore (add_many_entries 200));
  "many entries are added and remove_connection called", `Quick,
  (fun () -> ignore (add_and_remove_many_entries 500));
]

let fragmentation = [
  "to_cstruct no fragments", `Quick, test_to_cstruct_fragmentation_simple ;
  "to_cstruct fragments", `Quick, test_to_cstruct_fragmentation_basic ;
  "to_cstruct three fragments", `Quick, test_to_cstruct_fragmentation_three_full ;
  "to_cstruct errors due to don't fragment", `Quick, test_to_cstruct_fragmentation_error ;
  "into_cstruct no fragments", `Quick, test_into_cstruct_fragmentation_simple ;
  "into_cstruct fragments", `Quick, test_into_cstruct_fragmentation_basic ;
  "into_cstruct three fragments", `Quick, test_into_cstruct_fragmentation_three_full ;
  "into_cstruct errors due to don't fragment", `Quick, test_into_cstruct_fragmentation_error ;
  "of_ipv4_packet reassembles", `Quick, test_of_ipv4_packet_reassembly_basic ;
]

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level ~all:true (Some Logs.Debug);
  Alcotest.run "Mirage_nat.Nat_rewrite" [
    "correct_mappings", correct_mappings;
    "add_nat", add_nat;
    "add_redirect", add_redirect;
    "many_entries", many_entries;
    "fragmentation", fragmentation;
  ]
