open OUnit2

let zero_cstruct cs =
  let zero c = Cstruct.set_char c 0 '\000' in
  let i = Cstruct.iter (fun c -> Some 1) zero cs in
  Cstruct.fold (fun b a -> b) i cs

let basic_ipv4_frame proto src dst ttl smac_addr =
  (* copied from mirage-tcpip/lib/ipv4/allocate_frame, which unfortunately
    requires a whole ipv4 record type as an argument in order to extract the mac
     address from the record *)
  (* it would be nice to pull that out into a different function so test code
     could call allocate_frame with a Macaddr.t directly *)
  (* need to make sure this is zeroed, which we get for free w/io_page but not
     cstruct *)
  let ethernet_frame = zero_cstruct (Cstruct.create 1024) in (* altered *)
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
  let len = Wire_structs.sizeof_ethernet + Wire_structs.sizeof_ipv4 in
  (* len is sizeof_ethernet + sizezof_ipv4 *)
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
  (* we can do this resizing because we know that we originally requested a much
  larger buffer, but quite honestly this seems like a potentially extremely
    unsafe operation; TODO check in cstructs to see why this doesn't horribly
    explode more often *)
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
     checksum = 0 *)
  let just_ipv4 = Cstruct.sub ipv4 0 (Wire_structs.sizeof_ipv4) in
  assert_equal ~printer:string_of_int (Tcpip_checksum.ones_complement just_ipv4) 0

let test_tcp_ipv4 context = 
  let proto = 6 in
  let src = (Ipaddr.V4.of_string_exn "192.168.108.26") in
  let dst = (Ipaddr.V4.of_string_exn "4.141.2.6") in 
  let xl = (Ipaddr.V4.of_string_exn "128.104.108.1") in
  let smac_addr = Macaddr.of_string_exn "00:16:3e:ff:00:ff" in
  let ttl = 4 in
  let (frame, len) = basic_ipv4_frame proto src dst ttl smac_addr in
  let (frame, len) = add_tcp (frame, len) 255 1024 in
  let table = 
    match Lookup.insert (Hashtbl.create 2) proto
            ((V4 src), 255) ((V4 dst), 1024) ((V4 xl), 45454)
    with
    | Some t -> t
    | None -> assert_failure "Failed to insert test data into table structure"
  in
  let translated_frame = Rewrite.translate table 
      (Ipaddr.of_string_exn "128.104.108.1") Destination frame in
  match translated_frame with
  | None -> assert_failure "Expected translateable frame wasn't rewritten"
  | Some xl_frame ->
    (* check basic ipv4 stuff *)
    test_ipv4_rewriting src xl proto (ttl - 1) xl_frame;

    let xl_ipv4 = Cstruct.shift xl_frame (Wire_structs.sizeof_ethernet) in
    let xl_tcp = Cstruct.shift xl_ipv4 (Wire_structs.sizeof_ipv4) in
    (* check that src port is the same *)
    assert_equal 255 (Wire_structs.Tcp_wire.get_tcp_src_port xl_tcp);
    assert_equal 45454 (Wire_structs.Tcp_wire.get_tcp_dst_port xl_tcp);
    (* TODO: check checksum *)
    ()

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
  let translated_frame = Rewrite.translate table (Ipaddr.of_string_exn
                                                    "128.104.108.1") Destination frame in
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
    assert_equal ~printer:Cstruct.to_string xl_payload original_payload;

    let cs = 0 in
    assert_equal ~printer:string_of_int cs (Wire_structs.get_udp_checksum udp)

let test_udp_ipv6 context =
  assert_failure "Test not implemented :("

let test_tcp_ipv6 context =
  assert_failure "Test not implemented :("

let suite = "test-rewrite" >:::
            [
              "UDP IPv4 rewriting works" >:: test_udp_ipv4;
              "TCP IPv4 rewriting works" >:: test_tcp_ipv4 (* ;
              "UDP IPv6 rewriting works" >:: test_udp_ipv6;
              "TCP IPv6 rewriting works" >:: test_tcp_ipv6 *)
            ]

let () = 
  run_test_tt_main suite
