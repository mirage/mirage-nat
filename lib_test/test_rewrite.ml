open OUnit2

let zero_cstruct cs =
  let zero c = Cstruct.set_char c 0 '\000' in
  let i = Cstruct.iter (fun c -> Some 1) zero cs in
  Cstruct.fold (fun b a -> b) i cs

let basic_ipv4_frame ?(frame_size=1024) proto src dst ttl smac_addr =
  (* copied from mirage-tcpip/lib/ipv4/allocate_frame, which unfortunately
    requires a whole ipv4 record type as an argument in order to extract the mac
     address from the record *)
  (* it would be nice to pull that out into a different function so test code
     could call allocate_frame with a Macaddr.t directly *)
  (* need to make sure this is zeroed, which we get for free w/io_page but not
     cstruct *)
  let ethernet_frame = zero_cstruct (Cstruct.create frame_size) in (* altered *)
  Cstruct.set_len ethernet_frame (Wire_structs.sizeof_ethernet +
                                  Wire_structs.sizeof_ipv4);
  let smac = Macaddr.to_bytes smac_addr in (* altered *)
  Wire_structs.set_ethernet_src smac 0 ethernet_frame;
  Wire_structs.set_ethernet_ethertype ethernet_frame 0x0800;
  let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
  (* Write the constant IPv4 header fields *)
  Wire_structs.set_ipv4_hlen_version buf ((4 lsl 4) + (5)); 
  Wire_structs.set_ipv4_tos buf 0;
  Wire_structs.set_ipv4_off buf 0; 
  Wire_structs.set_ipv4_ttl buf ttl; 
  Wire_structs.set_ipv4_proto buf proto;
  Wire_structs.set_ipv4_src buf (Ipaddr.V4.to_int32 src); (* altered *)
  Wire_structs.set_ipv4_dst buf (Ipaddr.V4.to_int32 dst);
  Wire_structs.set_ipv4_id buf 0x4142;
  let len = Wire_structs.sizeof_ethernet + Wire_structs.sizeof_ipv4 in
  (ethernet_frame, len)

let basic_ipv6_frame proto src dst ttl smac_addr =
  let ethernet_frame = zero_cstruct (Cstruct.create
                                       (Wire_structs.sizeof_ethernet +
                                        Wire_structs.Ipv6_wire.sizeof_ipv6)) in (* altered *)
  let ip_layer = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in 
  let smac = Macaddr.to_bytes smac_addr in (* altered *)
  Wire_structs.set_ethernet_src smac 0 ethernet_frame;
  Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd;
  Wire_structs.Ipv6_wire.set_ipv6_version_flow ip_layer 0x60000000l;
  Wire_structs.Ipv6_wire.set_ipv6_src (Ipaddr.V6.to_bytes src) 0 ip_layer;
  Wire_structs.Ipv6_wire.set_ipv6_dst (Ipaddr.V6.to_bytes dst) 0 ip_layer;
  Wire_structs.Ipv6_wire.set_ipv6_nhdr ip_layer proto;
  Wire_structs.Ipv6_wire.set_ipv6_hlim ip_layer ttl;
  let len = Wire_structs.sizeof_ethernet + Wire_structs.Ipv6_wire.sizeof_ipv6 in
  (ethernet_frame, len)

let add_tcp (frame, len) source_port dest_port =
  let frame = Cstruct.set_len frame (len + Wire_structs.Tcp_wire.sizeof_tcp) in
  let tcp_buf = Cstruct.shift frame len in
  Wire_structs.Tcp_wire.set_tcp_src_port tcp_buf source_port;
  Wire_structs.Tcp_wire.set_tcp_dst_port tcp_buf dest_port;
  (* for now, all tcp packets have syn set & have a consistent seq # *)
  (* they also don't have options; options are for closers *)
  Wire_structs.Tcp_wire.set_tcp_sequence tcp_buf (Int32.of_int 0x432af310);
  Wire_structs.Tcp_wire.set_tcp_ack_number tcp_buf Int32.zero;
  Wire_structs.Tcp_wire.set_tcp_dataoff tcp_buf 5;
  Wire_structs.Tcp_wire.set_tcp_flags tcp_buf 2; (* syn *)
  Wire_structs.Tcp_wire.set_tcp_window tcp_buf 536; (* default_mss from tcp/window.ml *)
  (* leave checksum and urgent pointer unset *)
  (frame, len + Wire_structs.Tcp_wire.sizeof_tcp)

let add_udp (frame, len) source_port dest_port =
  (* also cribbed from mirage-tcpip *)
  let frame = Cstruct.set_len frame (len + Wire_structs.sizeof_udp) in
  let udp_buf = Cstruct.shift frame len in
  Wire_structs.set_udp_source_port udp_buf source_port;
  Wire_structs.set_udp_dest_port udp_buf dest_port;
  Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp (* + Cstruct.lenv
                                                                 bufs *));
  (* bufs is payload, which in our case is empty *)
  (* let csum = Ip.checksum frame (udp_buf (* :: bufs *) ) in 
  Wire_structs.set_udp_checksum udp_buf csum; *)
  (frame, len + Wire_structs.sizeof_udp)

let test_ipv4_rewriting exp_src exp_dst exp_proto exp_ttl xl_frame =
  (* should still be an ipv4 frame *)
  assert_equal 0x0800 (Wire_structs.get_ethernet_ethertype xl_frame);
  let ipv4 = Cstruct.shift xl_frame (Wire_structs.sizeof_ethernet) in

  (* source IP should be the same, since we said the direction should be
     Destination *)
  assert_equal (Ipaddr.V4.to_int32 exp_src) (Wire_structs.get_ipv4_src ipv4);

  (* destination IP should have been changed to the lookup address *)
  assert_equal ~printer:(fun a -> Ipaddr.V4.to_string (Ipaddr.V4.of_int32 a)) 
    (Ipaddr.V4.to_int32 (exp_dst)) 
    (Wire_structs.get_ipv4_dst ipv4);

  (* proto should be unaltered *)
  assert_equal ~printer:string_of_int exp_proto (Wire_structs.get_ipv4_proto ipv4);

  (* TTL should be the expected value, which the caller sets to k-1 *)
  assert_equal ~printer:string_of_int exp_ttl (Wire_structs.get_ipv4_ttl ipv4);

  (* IPv4 checksum should be correct, meaning that one's complement of packet +
     checksum = 0 *) (*
  let just_ipv4 = Cstruct.sub ipv4 0 (Wire_structs.sizeof_ipv4) in
  assert_equal ~printer:string_of_int 0 (Tcpip_checksum.ones_complement just_ipv4)
  *)
  
  ()

let basic_tcpv4 (direction : Rewrite.direction) proto ttl src dst xl sport dport xlport =
  let smac_addr = Macaddr.of_string_exn "00:16:3e:ff:00:ff" in
  let (frame, len) = 
    match direction with
    | Destination -> basic_ipv4_frame proto src dst ttl smac_addr 
    | Source -> basic_ipv4_frame proto dst xl ttl smac_addr
  in
  let frame, _ = 
    match direction with
    | Destination -> add_tcp (frame, len) sport dport 
    | Source -> add_tcp (frame, len) dport xlport 
  in
  let table = 
    match Lookup.insert (Hashtbl.create 2) proto
            ((V4 src), sport) ((V4 dst), dport) ((V4 xl), xlport)
    with
    | Some t -> t
    | None -> assert_failure "Failed to insert test data into table structure"
  in
  frame, table

let test_tcp_ipv4 context = 
  let ttl = 4 in
  let proto = 6 in
  let src = (Ipaddr.V4.of_string_exn "192.168.108.26") in
  let dst = (Ipaddr.V4.of_string_exn "4.141.2.6") in 
  let xl = (Ipaddr.V4.of_string_exn "128.104.108.1") in
  let sport, dport, xlport = 255,1024,45454 in
  let frame, table = basic_tcpv4 Destination proto ttl src dst xl sport dport xlport in
  let translated_frame = Rewrite.translate table Destination frame in
  match translated_frame with
  | None -> assert_failure "Expected translateable frame wasn't rewritten"
  | Some xl_frame ->
    (* check basic ipv4 stuff *)
    test_ipv4_rewriting src xl proto (ttl - 1) xl_frame;

    let xl_ipv4 = Cstruct.shift xl_frame (Wire_structs.sizeof_ethernet) in
    let xl_tcp = Cstruct.shift xl_ipv4 (Wire_structs.sizeof_ipv4) in
    let payload = Cstruct.shift xl_tcp (Wire_structs.Tcp_wire.sizeof_tcp) in
    (* check that src port is the same *)
    assert_equal sport (Wire_structs.Tcp_wire.get_tcp_src_port xl_tcp);
    (* dst port should have been rewritten *)
    assert_equal xlport (Wire_structs.Tcp_wire.get_tcp_dst_port xl_tcp);
    (* payload should be the same *)
    assert_equal (Cstruct.shift xl_frame (Wire_structs.sizeof_ethernet +
                                          Wire_structs.sizeof_ipv4 +
                                          Wire_structs.Tcp_wire.sizeof_tcp))
      payload;

  (* OK, apparently destination rewriting is all well and good; let's check
     source rewriting *)
    let frame, table = basic_tcpv4 Source proto ttl src dst xl sport dport xlport in
    let translated_frame = Rewrite.translate table Source frame in
    match translated_frame with
    | None -> assert_failure "Expected translateable frame wasn't rewritten"
    | Some xl_frame -> 
      (* check basic ipv4 stuff *)
      (* lookup (dst, xl) -> src, put src in dst column *)
      test_ipv4_rewriting dst src proto (ttl - 1) xl_frame;

      let xl_ipv4 = Cstruct.shift xl_frame (Wire_structs.sizeof_ethernet) in
      let xl_tcp = Cstruct.shift xl_ipv4 (Wire_structs.sizeof_ipv4) in
      let payload = Cstruct.shift xl_tcp (Wire_structs.Tcp_wire.sizeof_tcp) in
      (* check that src port is the same *)
      assert_equal dport(Wire_structs.Tcp_wire.get_tcp_src_port xl_tcp);
      (* dst port should have been rewritten *)
      assert_equal sport (Wire_structs.Tcp_wire.get_tcp_dst_port xl_tcp);
      (* payload should be the same *)
      assert_equal (Cstruct.shift xl_frame (Wire_structs.sizeof_ethernet +
                                            Wire_structs.sizeof_ipv4 +
                                            Wire_structs.Tcp_wire.sizeof_tcp))
        payload


    (* TODO: no checksum checking right now, since we leave that for the actual
sender to take care of *)

let test_udp_ipv4 context =
  let proto = 17 in
  let src = (Ipaddr.V4.of_string_exn "192.168.108.26") in
  let dst = (Ipaddr.V4.of_string_exn "4.141.2.6") in 
  let xl = (Ipaddr.V4.of_string_exn "128.104.108.1") in
  let smac_addr = Macaddr.of_string_exn "00:16:3e:ff:00:ff" in
  let ttl = 38 in
  let (frame, len) = basic_ipv4_frame proto src dst ttl smac_addr in
  let (frame, len) = add_udp (frame, len) 255 1024 in
  let table = 
    match Lookup.insert (Hashtbl.create 2) 17 
            ((V4 src), 255) ((V4 dst), 1024) ((V4 xl), 45454)
    with
    | Some t -> t
    | None -> assert_failure "Failed to insert test data into table structure"
  in
  let translated_frame = Rewrite.translate table Destination frame in
  match translated_frame with
  | None -> assert_failure "Expected translateable frame wasn't rewritten"
  | Some xl_frame ->
    (* check to see whether ipv4-level translation happened as expected *)
    test_ipv4_rewriting src xl proto (ttl - 1) xl_frame;

    (* UDP destination port should have changed *)
    let udp = Cstruct.shift xl_frame (Wire_structs.sizeof_ethernet + 
                                      Wire_structs.sizeof_ipv4) in
    assert_equal ~printer:string_of_int 45454 (Wire_structs.get_udp_dest_port
                                                 udp);

    (* payload should be unaltered *)
    let xl_payload = Cstruct.shift udp (Wire_structs.sizeof_udp) in
    let original_payload = Cstruct.shift frame (Wire_structs.sizeof_ethernet +
                                                Wire_structs.sizeof_ipv4 +
                                                Wire_structs.sizeof_udp) in
    assert_equal ~printer:Cstruct.to_string xl_payload original_payload
    (* TODO: checksum checks *)

let test_udp_ipv6 context =
  let proto = 17 in
  let interior_v6 = (Ipaddr.V6.of_string_exn "3333:aaa:bbbb:ccc::dd:ee") in
  let exterior_v6 = (Ipaddr.V6.of_string_exn "2a01:e35:2e8a:1e0::42:10") in
  let translate_v6 = (Ipaddr.V6.of_string_exn
                        "2604:3400:dc1:43:216:3eff:fe85:23c5") in
  let smac = Macaddr.of_string_exn "00:16:3e:c0:ff:ee" in
  let (frame, len) = basic_ipv6_frame proto interior_v6 exterior_v6 40 smac in
  let table =
    match Lookup.insert (Hashtbl.create 2) proto 
            ((V6 interior_v6), 255) 
            ((V6 exterior_v6), 1024) 
            ((V6 translate_v6), 45454)
    with
    | Some t -> t
    | None -> assert_failure "Failed to insert test data into table structure"
  in
  match Rewrite.translate table Destination frame with
  | None -> assert_failure "Couldn't translate an IPv6 UDP frame"
  | Some xl_frame -> assert_failure "Test not implemented :("

let test_make_entry_valid_pkt context =
  let proto = 17 in
  let src = Ipaddr.V4.of_string_exn "172.16.2.30" in
  let dst = Ipaddr.V4.of_string_exn "1.2.3.4" in
  let sport = 18787 in
  let dport = 80 in
  let xl_ip = Ipaddr.V4.of_string_exn "172.16.0.1" in
  let xl_port = 10201 in
  let smac_addr = Macaddr.of_string_exn "00:16:3e:65:65:65" in
  let table = Lookup.empty () in
  let (frame, len) = basic_ipv4_frame proto src dst 52 smac_addr in
  let (frame, len) = add_udp (frame, len) sport dport in
  match Rewrite.make_entry table frame (Ipaddr.V4 xl_ip) xl_port with
  | Overlap -> assert_failure "make_entry claimed overlap when inserting into an
                 empty table"
  | Unparseable -> 
    Printf.printf "Allegedly unparseable frame follows:\n";
    Cstruct.hexdump frame;
    assert_failure "make_entry claimed that a reference packet was unparseable"
  | Ok t ->
    (* make sure table actually has the entries we expect *)
    let check_entries src_lookup dst_lookup = 
      (* TODO: rewrite this; assert_equal and a printer function would be
         clearer *)
      match src_lookup, dst_lookup with
      | Some (xl_ip, xl_port), Some (src, sport) -> assert_equal 1 1 (* yay! *)
      | Some (q_ip, q_port), Some (r_ip, r_port) -> 
        let err = Printf.sprintf "Bad entry from make_entry: %s, %d; %s, %d\n" 
            (Ipaddr.to_string q_ip) q_port (Ipaddr.to_string r_ip) r_port in
        assert_failure err
      | None, None -> assert_failure 
        "make_entry claimed success, but was missing expected entries entirely"
    in
    let src_lookup = Lookup.lookup t proto (V4 src, sport) (V4 dst, dport) in
    let dst_lookup = Lookup.lookup t proto (V4 dst, dport) (V4 xl_ip, xl_port) in
    check_entries src_lookup dst_lookup;
    (* trying the same operation again should give us an Overlap failure *)
    match Rewrite.make_entry t frame (Ipaddr.V4 xl_ip) xl_port with
    | Overlap -> ()
    | Unparseable -> 
      Printf.printf "Allegedly unparseable frame follows:\n";
      Cstruct.hexdump frame;
      assert_failure "make_entry claimed that a reference packet was unparseable"
    | Ok t -> assert_failure "make_entry allowed a duplicate entry"

let test_make_entry_nonsense context =
  (* sorts of bad packets: broadcast packets,
     non-tcp/udp/icmp packets *)
  let proto = 17 in
  let src = Ipaddr.V4.of_string_exn "172.16.2.30" in
  let dst = Ipaddr.V4.of_string_exn "1.2.3.4" in
  let xl_ip = Ipaddr.V4.of_string_exn "172.16.0.1" in
  let xl_port = 10201 in
  let smac_addr = Macaddr.of_string_exn "00:16:3e:65:65:65" in
  let frame_size = (Wire_structs.sizeof_ethernet + Wire_structs.sizeof_ipv4) in
  let mangled_looking, _ = basic_ipv4_frame ~frame_size proto src dst 60 smac_addr in
  match (Rewrite.make_entry (Lookup.empty ()) mangled_looking
           (Ipaddr.V4 xl_ip) xl_port) with
  | Overlap -> assert_failure "make_entry claimed a mangled packet was already
  in the table"
  | Ok t -> assert_failure "make_entry happily took a mangled packet"
  | Unparseable -> 
    let broadcast_dst = Ipaddr.V4.of_string_exn "255.255.255.255" in
    let sport = 45454 in
    let dport = 80 in
    let broadcast, _ = add_tcp (basic_ipv4_frame 6 src broadcast_dst 30 smac_addr)
        sport dport in
    match (Rewrite.make_entry (Lookup.empty ()) broadcast (Ipaddr.V4 xl_ip)
             xl_port) with
    | Ok _ | Overlap -> assert_failure "make_entry happily took a broadcast
    packet"
    | Unparseable -> 
      (* try just an ethernet frame *)
      let e = zero_cstruct (Cstruct.create Wire_structs.sizeof_ethernet) in
      match (Rewrite.make_entry (Lookup.empty ()) e (Ipaddr.V4 xl_ip) xl_port)
      with
      | Ok _ | Overlap -> assert_failure "make_entry claims to have succeeded
      with a bare ethernet frame"
      | Unparseable -> ()

let test_tcp_ipv6 context =
  assert_failure "Test not implemented :("

let suite = "test-rewrite" >:::
            [
              "UDP IPv4 rewriting works" >:: test_udp_ipv4;
              "TCP IPv4 rewriting works" >:: test_tcp_ipv4 (* ;
              "UDP IPv6 rewriting works" >:: test_udp_ipv6;
                                                              "TCP IPv6 rewriting works" >:: test_tcp_ipv6 *) ;
              "make_entry makes entries" >:: test_make_entry_valid_pkt;
              "make_entry refuses nonsense frames" >:: test_make_entry_nonsense
            ]

let () = 
  run_test_tt_main suite
