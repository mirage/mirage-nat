open Ipaddr
open Mirage_nat
open Test_lib
open Lwt.Infix

type direction = | Source | Destination

let int_of_protocol = function
  | Udp -> 17
  | Tcp -> 6
  | Icmp -> 1

let ipv4_of_str = Ipaddr.V4.of_string_exn

let mapping =
  let module M = struct
    type t = (Ipaddr.t * int) * (Ipaddr.t * int)
    let pp fmt (left, right) =
      Format.fprintf fmt "(%a, %d) -> (%a, %d)"
      Ipaddr.pp_hum (fst left) (snd left)
      Ipaddr.pp_hum (fst right) (snd right)
    let equal l r =
      let pair_equal (l_ip, (l_port : int)) (r_ip, r_port) =
        match Ipaddr.compare l_ip r_ip with
        | 0 -> Pervasives.compare l_port r_port = 0
        | n -> false
      in
      match pair_equal (fst l) (fst r) with
      | false -> false
      | true -> pair_equal (snd l) (snd r)
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let ip =
  let module M = struct
    type t = Ipaddr.V4.t
    let pp = Ipaddr.V4.pp_hum
    let equal p q = (Ipaddr.V4.compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let cstruct =
  let module M = struct
    type t = Cstruct.t
    let pp = Cstruct.hexdump_pp
    let equal = Cstruct.equal
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let packet_t = (module Nat_packet : Alcotest.TESTABLE with type t = Nat_packet.t)

module Rewriter = Mirage_nat_hashtable.Make(Mclock)(Unix_time)

let clock = Lwt_main.run (Mclock.connect ())

module Default_values = struct
  let smac_addr = Macaddr.of_string_exn "00:16:3e:5e:6c:09"
  let dmac_addr = Macaddr.of_string_exn "10:9a:dd:63:00:05"
  let src = (ipv4_of_str "192.168.108.26")
  let dst = (ipv4_of_str "4.141.2.6")
  let xl = (ipv4_of_str "128.104.108.1")
  let src_port, dst_port, xlport = 255, 1024, 45454
  let payload = Cstruct.of_string "adorable_cat_photo.jpg"
end


module Constructors = struct

  let full_packet ~payload ~proto ~ttl ~src ~dst ~src_port ~dst_port =
    let transport = match proto with
    | Icmp -> assert false
    | Udp -> `UDP ({Udp_packet.src_port = src_port; dst_port = dst_port}, payload)
    | Tcp -> `TCP (
        {Tcp.Tcp_packet.src_port = src_port; dst_port = dst_port;
         sequence = Tcp.Sequence.of_int 0x432af310;
         ack_number = Tcp.Sequence.zero;
         urg = false; ack = false; psh = false; rst = false; syn = true; fin = false;
         window = 536;
         options = []; (* If this is changed, need to change the length sent to `pseudoheader` above *)
        }, payload)
    in
    let ip = { Ipv4_packet.src; dst; proto = int_of_protocol proto; ttl; options = (Cstruct.create 0) } in
    `IPv4 (ip, transport)
 
  let ip_packet_and_redirect_table direction
      ~proto ~ttl
      ~outside_src ~external_xl ~internal_xl ~internal_client
      ~outside_src_port ~external_xl_port ~internal_xl_port ~internal_client_port =
    let ip_packet =
      match direction with
      | Source -> full_packet ~payload:Default_values.payload ~proto ~ttl
                    ~src:outside_src ~dst:external_xl
                    ~src_port:outside_src_port ~dst_port:external_xl_port
      | Destination -> full_packet ~payload:Default_values.payload ~proto ~ttl
                         ~src:internal_xl ~dst:internal_client
                         ~src_port:internal_xl_port ~dst_port:internal_client_port
    in
    let table () =
      let open Rewriter in
      empty clock >>= fun t ->
      add_redirect t ip_packet
          ((V4 internal_xl), internal_xl_port)
          ((V4 internal_client), internal_client_port) >>= function
      | Ok () -> Lwt.return t
      | Error _ -> Alcotest.fail "Failed to insert test data into table structure"
    in
    table () >>= fun table -> Lwt.return (ip_packet, table)

  let ip_packet_and_nat_table
      ~proto ~ttl ~src ~dst ~xl ~src_port ~dst_port ~xlport =
    let ip_packet = full_packet ~payload:Default_values.payload ~proto ~ttl ~src ~dst ~src_port ~dst_port in
    Format.printf "made reference packet: %a@." Nat_packet.pp ip_packet;
    let table () =
      let open Rewriter in
      empty clock >>= fun t ->
      add_nat t ip_packet ((V4 xl), xlport) >>= function
      | Ok () -> Lwt.return t
      | Error _ -> Alcotest.fail "Failed to insert test data into table structure"
    in
    table () >>= fun table -> Lwt.return (ip_packet, table)

end

let check_entry expected (actual : ((Ipaddr.t * int) * (Ipaddr.t * int)) option) =
  match actual with
  | Some a -> Alcotest.check mapping expected a
  | None -> Alcotest.fail "an expected entry was missing entirely"

(* given a source IP, destination IP, protocol, and TTL,
   check to see whether an IPv4 packet has those fields set. *)
let assert_ipv4_has exp_src exp_dst exp_proto exp_ttl = function
  | `IPv4 (ipv4_header, ipv4_payload) ->
    let open Ipv4_packet in
    Alcotest.check ip "ip src" exp_src ipv4_header.src;
    Alcotest.check ip "ip dst" exp_dst ipv4_header.dst;
    Alcotest.check Alcotest.int "protocol" (int_of_protocol exp_proto) ipv4_header.proto;
    Alcotest.check Alcotest.int "ttl" exp_ttl ipv4_header.ttl

let assert_transport_has exp_src_port exp_dst_port = function
  | `IPv4 (_, `ICMP _) -> assert false
  | `IPv4 (_, `TCP (tcp, _)) ->
    let src_port, dst_port = Tcp.Tcp_packet.(tcp.src_port, tcp.dst_port) in
    Alcotest.check Alcotest.int "source port" exp_src_port src_port;
    Alcotest.check Alcotest.int "destination port" exp_dst_port dst_port
  | `IPv4 (_, `UDP (udp, _)) ->
    let src_port, dst_port = Udp_packet.(udp.src_port, udp.dst_port) in
    Alcotest.check Alcotest.int "source port" exp_src_port src_port;
    Alcotest.check Alcotest.int "destination port" exp_dst_port dst_port

let assert_payloads_match expected actual =
  let `IPv4 (_, expected) = expected in
  let `IPv4 (_, actual) = actual in
  match expected, actual with
  | `ICMP _, `ICMP _ -> assert false
  | `TCP (_, expected), `TCP (_, actual)
  | `UDP (_, expected), `UDP (_, actual) ->
    Alcotest.check cstruct "Payload match failure" expected actual
  | _ ->
    Alcotest.fail "Packets are from different protocols!"

let assert_checksum_correct raw =
  Format.printf "Check %a@." Cstruct.hexdump_pp raw;
  match Ipv4_packet.Unmarshal.of_cstruct raw with
  | Error e -> Alcotest.fail (Fmt.strf "assert_checksum failed: %s" e)
  | Ok (ipv4_header, transport_packet) ->
    Printf.printf "ipv4_header len = %d\n" (Cstruct.len raw - Cstruct.len transport_packet);
    let proto =
      match Ipv4_packet.(Unmarshal.int_to_protocol ipv4_header.proto) with
      | Some (`TCP | `UDP as p) -> p
      | _ -> assert false
    in
    Alcotest.(check bool) "Transport checksum correct" true
      (Ipv4_packet.Unmarshal.verify_transport_checksum ~ipv4_header ~transport_packet ~proto)

let assert_translates table packet =
  Rewriter.translate table packet >>= function
  | Error `Untranslated -> Alcotest.fail "Expected translateable packet wasn't rewritten"
  | Ok packet ->
    Format.printf "packet translated OK: %a...@." Nat_packet.pp packet;
    let raw = Cstruct.concat @@ Nat_packet.to_cstruct packet in
    assert_checksum_correct raw;
    match Nat_packet.of_ipv4_packet raw with
    | Ok loaded when Nat_packet.equal packet loaded -> Lwt.return packet
    | Ok loaded -> Alcotest.fail (Fmt.strf "Packet changed by save/load! Saved:@.%a@.Got:@.%a"
                                    Nat_packet.pp packet
                                    Nat_packet.pp loaded
                                 )
    | Error e   -> Alcotest.fail (Fmt.strf "Failed to load saved packet! Saved:@.%a@.As:@.%a@.Error: %a"
                                    Nat_packet.pp packet
                                    Cstruct.hexdump_pp raw
                                    Nat_packet.pp_error e
                                 )

let test_nat_ipv4 proto =
  let ttl = 4 in
  let open Default_values in
  Constructors.ip_packet_and_nat_table ~proto ~ttl ~src ~dst ~xl ~src_port
    ~dst_port ~xlport >>= fun (translated_packet, table) ->
  Constructors.ip_packet_and_nat_table ~proto ~ttl ~src ~dst ~xl ~src_port
    ~dst_port ~xlport >>= fun (untranslated_packet, _) ->
  assert_translates table translated_packet >>= fun translated_packet ->
  assert_payloads_match untranslated_packet untranslated_packet;
  Printf.printf "untranslated packet matched itself, yay!\n";
  assert_payloads_match translated_packet translated_packet;
  Printf.printf "translated packet matched itself, yay!\n";
  assert_payloads_match untranslated_packet translated_packet;
  assert_ipv4_has xl dst proto (ttl - 1) translated_packet;
  assert_transport_has xlport dst_port translated_packet;
  Lwt.return_unit

let test_add_redirect_valid_pkt () =
  let proto = Udp in
  let internal_client = ipv4_of_str "172.16.2.30" in
  let outside_requester = ipv4_of_str "1.2.3.4" in
  let nat_external_ip = ipv4_of_str "208.121.103.4" in
  let nat_internal_ip = ipv4_of_str "172.16.2.1" in
  let internal_client_port, outside_requester_port,
      nat_external_port, nat_internal_port = 18787, 80, 80, 8989 in
  Constructors.ip_packet_and_redirect_table Source ~proto ~ttl:52
    ~outside_src:outside_requester ~external_xl:nat_external_ip
    ~outside_src_port:outside_requester_port ~external_xl_port:nat_external_port
    ~internal_xl:nat_internal_ip ~internal_xl_port:nat_internal_port
    ~internal_client:internal_client ~internal_client_port:internal_client_port
  >>= fun (packet, table) ->
  assert_translates table packet >>= fun packet ->
  let orig_packet = Constructors.full_packet ~proto ~ttl:52 ~src:outside_requester
      ~dst:nat_external_ip ~src_port:outside_requester_port
      ~dst_port:nat_external_port ~payload:Default_values.payload
  in
  assert_payloads_match packet orig_packet;
  (* return direction packet translates too *)
  let reverse_packet =
    Constructors.full_packet ~proto ~ttl:52 ~src:internal_client
      ~src_port:internal_client_port ~dst:nat_internal_ip ~dst_port:nat_internal_port
      ~payload:Default_values.payload
  in
  assert_translates table reverse_packet >>= fun reverse_packet ->
  let orig_reverse_packet =
    Constructors.full_packet ~proto ~ttl:52 ~src:internal_client
      ~src_port:internal_client_port ~dst:nat_internal_ip ~dst_port:nat_internal_port
      ~payload:Default_values.payload
  in
  assert_payloads_match reverse_packet orig_reverse_packet;
  let open Rewriter in
  add_redirect table orig_packet
    ((Ipaddr.V4 nat_internal_ip), nat_internal_port)
    ((Ipaddr.V4 internal_client), internal_client_port) >>= function
    | Error `Overlap -> Alcotest.fail "overlap claimed for update of entry"
    | Error `Cannot_NAT ->
      Format.printf "Allegedly unNATable frame follows: %a@." Nat_packet.pp orig_packet;
      Alcotest.fail "add_redirect claimed that a reference packet was unNATable"
    | Ok () ->
      (* attempting to add another entry which partially overlaps should fail *)
      add_redirect table orig_packet
        ((Ipaddr.of_string_exn "8.8.8.8"), nat_internal_port)
        ((Ipaddr.V4 internal_client), internal_client_port) >>= function
      | Error `Overlap -> Lwt.return_unit
      | Ok () -> Alcotest.fail "overlapping entry addition allowed"
      | Error `Cannot_NAT ->
        Format.printf "Allegedly unNATable frame follows: %a@." Nat_packet.pp orig_packet;
        Alcotest.fail "add_redirect claimed that a reference packet was unNATable"

let test_add_nat_valid_pkt () =
  let open Default_values in
  let proto = Udp in
  let payload = Cstruct.of_string "GET / HTTP/1.1\r\n" in
  let frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src ~dst ~src_port ~dst_port in
  let open Rewriter in
  empty clock >>= fun table ->
  add_nat table frame ((V4 xl), xlport) >>= function
  | Error `Overlap -> Alcotest.fail "add_nat claimed overlap when inserting into an
                 empty table"
  | Error `Cannot_NAT ->
    Format.printf "Allegedly unNATable frame follows: %a@." Nat_packet.pp frame;
    Alcotest.fail "add_nat claimed that the first reference packet was unNATable"
  | Ok () ->
    (* make sure table actually has the entries we expect *)
    assert_translates table frame >>= fun frame ->
    let orig_frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src ~dst ~src_port ~dst_port in
    assert_payloads_match frame orig_frame;
    let reverse_frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:dst ~dst:xl
        ~src_port:dst_port ~dst_port:xlport in
    assert_translates table reverse_frame >>= fun reverse_frame ->
    let orig_reverse_frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:dst ~dst:xl
        ~src_port:dst_port ~dst_port:xlport in
    assert_payloads_match orig_reverse_frame reverse_frame;
    let open Rewriter in
    (* trying the same operation again should update the expiration time *)
    add_nat table orig_frame ((V4 xl), xlport) >>= function
    | Error `Overlap -> Alcotest.fail "add_nat disallowed an update"
    | Error `Cannot_NAT ->
      Format.printf "Allegedly unNATable frame follows: %a@." Nat_packet.pp frame;
      Alcotest.fail "add_nat claimed that a reference packet was unNATable"
    | Ok () ->
      (* a half-match should fail with Overlap *)
      let frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:xl ~dst ~src_port ~dst_port in
      add_nat table frame ((Ipaddr.V4 xl), xlport) >>= function
      | Ok () -> Alcotest.fail "overlap wasn't detected"
      | Error `Cannot_NAT ->
        Format.printf "Allegedly unNATable frame follows: %a@." Nat_packet.pp frame;
        Alcotest.fail "add_nat claimed that a reference packet was unNATable"
      | Error `Overlap -> Lwt.return_unit


(*
let test_add_nat_nonsense () =
  (* TODO: also test broadcast packets, non-tcp/udp/icmp packets *)
  let open Default_values in
  let proto = Udp in
  let payload = Cstruct.of_string "SET PASV" in
  let mangled_looking = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:xl ~dst ~src_port ~dst_port in
  Ipv4_wire.set_ipv4_hlen_version (Cstruct.shift mangled_looking Ethif_wire.sizeof_ethernet) 0xff;
  let open Rewriter in
  empty clock >>= fun t ->
  add_nat t mangled_looking ((Ipaddr.V4 xl), xlport) >>= function
  | Ok -> Alcotest.fail "add_nat happily took a mangled packet"
  | Overlap -> Alcotest.fail
                 "add_nat claimed a mangled packet was already in the table"
  | Unparseable -> Lwt.return_unit
*)

let test_add_nat_broadcast () =
  let open Default_values in
  let broadcast_dst = ipv4_of_str "255.255.255.255" in
  let broadcast = Constructors.full_packet ~payload ~proto:Tcp ~ttl:30 ~src
                    ~dst:broadcast_dst ~src_port ~dst_port in
  let open Rewriter in
  empty clock >>= fun t ->
  add_nat t broadcast ((Ipaddr.V4 xl), xlport) >>= function
  | Ok () | Error `Overlap -> Alcotest.fail "add_nat operated on a broadcast packet"
  | Error `Cannot_NAT ->
    (* try just an ethernet frame *)
    let e = Cstruct.create Ethif_wire.sizeof_ethernet in
    match Nat_packet.of_ethernet_frame e with
    | Ok _ ->
      Alcotest.fail "of_ethernet_frame claims to have succeeded with a bare ethernet frame"
    | Error _ -> Lwt.return_unit

type packet_variables = {
  src : Ipaddr.V4.t;
  dst : Ipaddr.V4.t;
  ttl : Cstruct.uint8;
  src_port : Cstruct.uint16;
  dst_port : Cstruct.uint16;
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
    let src_port = random_port () in
    let dst_port = random_port () in
    let ttl = random_ttl () in
    let r = { src; dst; src_port; dst_port; ttl } in
    (Constructors.full_packet ~payload:Default_values.payload ~proto:Tcp ~ttl ~src ~dst ~src_port ~dst_port, r)
  in
  (* test results are a little easier to reason about if we mimic the expected
     behaviour of users -- NATting stuff from gateway IP to another IP
     downstream from a gateway, both of which are fixed *)
  Random.self_init ();
  let fixed_internal_ip = random_ipv4 () in
  let fixed_external_ip = random_ipv4 () in
  let open Rewriter in
  empty clock >>= fun t ->
  let rec shove_entries = function
    | n when n <= 0 -> Lwt.return_unit
    | n ->
      Printf.printf "%d more entries...\n%!" n;
      let (packet, values) = random_packet () in
      translate t packet >>= function
      | Ok _ ->
        Printf.printf "already a Source entry for the packet; trying again\n%!";
        shove_entries n (* generated an overlap; try again *)
      | Error `Untranslated ->
        translate t packet >>= function
        | Ok _ ->
          Printf.printf "already a Destination entry for the packet; trying again\n%!";
          shove_entries n
        | Error `Untranslated ->
          (* bias creation of NAT rules over redirects *)
          begin
            match (Random.int 10) with
            | 0 ->
              Printf.printf "adding a redirect rule\n%!";
              Rewriter.add_redirect t packet ((V4 fixed_external_ip), random_port ())
                ((V4 fixed_internal_ip), random_port ())
            | _ ->
              Printf.printf "adding a NAT rule\n%!";
              Rewriter.add_nat t packet ((V4 fixed_external_ip), random_port ())
          end >>= function
          | Error `Cannot_NAT ->
            let print_ip ip = Printf.sprintf "%x (%s)"
                (Int32.to_int (Ipaddr.V4.to_int32 ip))
                (Ipaddr.V4.to_string ip) in
            Printf.printf "With %d entries yet to go,
            Failure parsing this packet, which was automatically generated from
            the following values:\n" n;
            Printf.printf "source: %s, %x\n" (print_ip values.src) values.src_port;
            Printf.printf "destination: %s, %x\n" (print_ip values.dst) values.dst_port;
            Printf.printf "ttl: %x\n" values.ttl;
            Format.printf "%a@." Nat_packet.pp packet;
            Alcotest.fail "Parse failure"
          | Error `Overlap ->
            Printf.printf "overlap between entries; trying again\n%!";
            shove_entries n
          | Ok () -> shove_entries (n-1)
  in
  shove_entries how_many

let make_icmp ~src ~dst ~payload ~ttl icmp =
  let src = Ipaddr.V4.of_string_exn src in
  let dst = Ipaddr.V4.of_string_exn dst in
  let proto = Ipv4_packet.Marshal.protocol_to_int `ICMP in
  let icmp =
    match icmp with
    | `Echo_request (id, seq) -> {
        Icmpv4_packet.ty = Icmpv4_wire.Echo_request;
        code = 0;
        subheader = Icmpv4_packet.Id_and_seq (id, seq)
      } 
    | `Echo_reply (id, seq) -> {
        Icmpv4_packet.ty = Icmpv4_wire.Echo_reply;
        code = 0;
        subheader = Icmpv4_packet.Id_and_seq (id, seq)
      } 
  in
  let ip = {Ipv4_packet.src; dst; ttl; options = Cstruct.create 0; proto} in
  `IPv4 (ip, `ICMP (icmp, payload))

let test_add_icmp () =
  Rewriter.empty clock >>= fun t ->
  let payload = Cstruct.create 0 in
  let packet = make_icmp ~src:"192.168.1.5" ~dst:"8.8.8.8" ~payload (`Echo_request (5, 9)) ~ttl:64 in
  let endpoint = Ipaddr.of_string_exn "82.1.1.8", 81 in
  (* Add rule *)
  Rewriter.add_nat t packet endpoint
  >|= Alcotest.(check (result unit (of_pp Mirage_nat.pp_error))) "Add ICMP rule" (Ok ()) >>= fun () ->
  (* Translate outgoing request *)
  let expected = make_icmp ~src:"82.1.1.8" ~dst:"8.8.8.8" ~payload (`Echo_request (81, 9)) ~ttl:63 in
  Rewriter.translate t packet
  >|= Alcotest.(check (result packet_t (of_pp Mirage_nat.pp_error))) "Apply ICMP rule" (Ok expected) >>= fun () ->
  (* Translate reply *)
  let packet = make_icmp ~dst:"82.1.1.8" ~src:"8.8.8.8" ~payload (`Echo_reply (81, 9)) ~ttl:64 in
  let expected = make_icmp ~dst:"192.168.1.5" ~src:"8.8.8.8" ~payload (`Echo_reply (5, 9)) ~ttl:63 in
  Rewriter.translate t packet
  >|= Alcotest.(check (result packet_t (of_pp Mirage_nat.pp_error))) "Map ICMP reply" (Ok expected) >>= fun () ->
  Lwt.return ()

let lwt_run f () = Lwt_main.run (f ())

let correct_mappings =
  [
    "IPv4 UDP NAT rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Udp) ;
    "IPv4 TCP NAT rewrites", `Quick, lwt_run (fun () -> test_nat_ipv4 Tcp) ;
  ]

let add_nat = [
  "add_nat makes entries",            `Quick, lwt_run test_add_nat_valid_pkt;
  "add_nat refuses broadcast frames", `Quick, lwt_run test_add_nat_broadcast;
  "add_nat for ICMP",                 `Quick, lwt_run test_add_icmp;
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

let () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level ~all:true (Some Logs.Debug);
  Alcotest.run "Mirage_nat.Nat_rewrite" [
    "correct_mappings", correct_mappings;
    "add_nat", add_nat;
    "add_redirect", add_redirect;
    "many_entries", many_entries;
  ]
