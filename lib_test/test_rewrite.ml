open Ipaddr
open Mirage_nat
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

  let full_packet ~payload ~proto ~ttl ~src ~dst ~src_port ~dst_port =
    let transport = match proto with
    | Udp ->
       let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP (Cstruct.len payload) in
       Udp_packet.(Marshal.make_cstruct ~pseudoheader ~payload {src_port = src_port; dst_port = dst_port;})
    | Tcp ->
       let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`TCP (Cstruct.len payload) in
       Tcp.Tcp_packet.(Marshal.make_cstruct ~pseudoheader ~payload
       {src_port = src_port; dst_port = dst_port;
        sequence = Tcp.Sequence.of_int 0x432af310;
        ack_number = Tcp.Sequence.zero;
        urg = false; ack = false; psh = false; rst = false; syn = true; fin = false;
        window = 536;
        options = [];
       })
    in
    let ip = Ipv4_packet.(Marshal.make_cstruct ~payload:transport { src; dst; proto = int_of_protocol proto; ttl; options = (Cstruct.create 0) }) in
    Cstruct.concat [ip; transport; payload]
 
  let ip_packet_and_redirect_table direction
      ~proto ~ttl
      ~outside_src ~external_xl ~internal_xl ~internal_client
      ~outside_src_port ~external_xl_port ~internal_xl_port ~internal_client_port =
    let ip_packet =
      match direction with
      | Source -> full_packet ~payload:(Cstruct.create 0) ~proto ~ttl
                    ~src:outside_src ~dst:external_xl
                    ~src_port:outside_src_port ~dst_port:external_xl_port
      | Destination -> full_packet ~payload:(Cstruct.create 0) ~proto ~ttl
                         ~src:internal_xl ~dst:internal_client
                         ~src_port:internal_xl_port ~dst_port:internal_client_port
    in
    let table () =
      let open Rewriter in
      empty () >>= fun t ->
      add_redirect t ip_packet
          ((V4 internal_xl), internal_xl_port)
          ((V4 internal_client), internal_client_port) >>= function
      | Ok -> Lwt.return t
      | Overlap | Unparseable -> Alcotest.fail "Failed to insert test data into table structure"
    in
    table () >>= fun table -> Lwt.return (ip_packet, table)

  let ip_packet_and_nat_table
      ~proto ~ttl ~src ~dst ~xl ~src_port ~dst_port ~xlport =
    let ip_packet = full_packet ~payload:(Cstruct.create 0) ~proto ~ttl ~src ~dst ~src_port ~dst_port in
    let table () =
      let open Rewriter in
      empty () >>= fun t ->
      add_nat t ip_packet ((V4 xl), xlport) >>= function
      | Ok -> Lwt.return t
      | Overlap | Unparseable -> Alcotest.fail "Failed to insert test data into table structure"
    in
    table () >>= fun table -> Lwt.return (ip_packet, table)

end

module Default_values = struct
  let smac_addr = Macaddr.of_string_exn "00:16:3e:ff:00:ff"
  let src = (ipv4_of_str "192.168.108.26")
  let dst = (ipv4_of_str "4.141.2.6")
  let xl = (ipv4_of_str "128.104.108.1")
  let src_port, dst_port, xlport = 255, 1024, 45454
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
   check to see whether an IPv4 packet has those fields set. *)
let assert_ipv4_has exp_src exp_dst exp_proto exp_ttl ipv4 =
  let printer = Ipaddr.V4.to_string in
  match Ipv4_packet.Unmarshal.of_cstruct ipv4 with
  | Result.Error s -> Alcotest.fail s
  | Result.Ok (ipv4_header, ipv4_payload) ->
    assert_equal ~printer exp_src ipv4_header.src;
    assert_equal ~printer exp_dst ipv4_header.dst;
    assert_equal ~printer:string_of_int (int_of_protocol exp_proto) ipv4_header.proto;
    assert_equal ~printer:string_of_int exp_ttl ipv4_header.ttl

let assert_transport_has exp_src_port exp_dst_port xl_frame =
  match Nat_decompose.decompose xl_frame with
  | Result.Error s -> Alcotest.fail s
  | Result.Ok { ethernet; network; transport } ->
    match Nat_decompose.ports transport with
    | None -> Alcotest.fail "no transport layer in a translated packet"
    | Some (proto, transport, src_port, dst_port) ->
    OUnit.assert_equal exp_src_port src_port;
    OUnit.assert_equal exp_dst_port dst_port

let assert_payloads_match expected actual =
  let check () =
  let (>>=) = Rresult.(>>=) in
  Nat_decompose.decompose expected >>= fun expected ->
  Nat_decompose.decompose actual >>= fun actual ->
  match expected.transport, actual.transport with
  | None, _ | _, None -> Result.Error "no transport in a payload match"
  | Some (Udp (_, expected)), Some (Udp (_, actual)) ->
  OUnit.assert_equal ~msg:"Payload match failure"
                     ~cmp:(fun a b -> 0 = Cstruct.compare a b)
                     expected actual;
                     Result.Ok ()
  in
  match check () with
  | Result.Error s -> Alcotest.fail s
  | Result.Ok () -> ()


let assert_translates table direction frame =
  Rewriter.translate table frame >>= function
  | Untranslated -> Alcotest.fail "Expected translateable frame wasn't rewritten"
  | Translated -> Lwt.return_unit

let test_nat_ipv4 proto =
  let ttl = 4 in
  let open Default_values in
  Constructors.ip_packet_and_nat_table ~proto ~ttl ~src ~dst ~xl ~src_port
    ~dst_port ~xlport >>= fun (translated_packet, table) ->
  assert_translates table Source translated_packet >>= fun () ->
  Constructors.ip_packet_and_nat_table ~proto ~ttl ~src ~dst ~xl ~src_port
    ~dst_port ~xlport >>= fun (untranslated_packet, _) ->
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
  let frame = Constructors.full_packet ~proto ~ttl:52 ~src:outside_requester
      ~dst:nat_external_ip ~src_port:outside_requester_port
      ~dst_port:nat_external_port ~payload:(Cstruct.create 0)
  in
  Constructors.ip_packet_and_redirect_table Source ~proto ~ttl:52
    ~outside_src:outside_requester ~external_xl:nat_external_ip
    ~outside_src_port:outside_requester_port ~external_xl_port:nat_external_port
    ~internal_xl:nat_internal_ip ~internal_xl_port:nat_internal_port
    ~internal_client:internal_client ~internal_client_port:internal_client_port
  >>= fun (frame, table) ->
  assert_translates table Source frame >>= fun () ->
  let orig_frame = Constructors.full_packet ~proto ~ttl:52 ~src:outside_requester
      ~dst:nat_external_ip ~src_port:outside_requester_port
      ~dst_port:nat_external_port ~payload:(Cstruct.create 0)
  in
  assert_payloads_match frame orig_frame;
  (* return direction frame translates too *)
  let reverse_packet =
    Constructors.full_packet ~proto ~ttl:52 ~src:internal_client
      ~src_port:internal_client_port ~dst:nat_internal_ip ~dst_port:nat_internal_port
      ~payload:(Cstruct.create 0)
  in
  assert_translates table Destination reverse_packet >>= fun () ->
  let orig_reverse_packet =
    Constructors.full_packet ~proto ~ttl:52 ~src:internal_client
      ~src_port:internal_client_port ~dst:nat_internal_ip ~dst_port:nat_internal_port
      ~payload:(Cstruct.create 0)
  in
  assert_payloads_match reverse_packet orig_reverse_packet;
  let open Rewriter in
  add_redirect table orig_frame
    ((Ipaddr.V4 nat_internal_ip), nat_internal_port)
    ((Ipaddr.V4 internal_client), internal_client_port) >>= function
    | Overlap -> Alcotest.fail "overlap claimed for update of entry"
    | Unparseable ->
      Printf.printf "Allegedly unparseable frame follows:\n";
      Cstruct.hexdump frame;
      Alcotest.fail "add_redirect claimed that a reference packet was unparseable"
    | Ok ->
      (* attempting to add another entry which partially overlaps should fail *)
      add_redirect table orig_frame
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
  let payload = Cstruct.of_string "GET / HTTP/1.1\r\n" in
  let frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src ~dst ~src_port ~dst_port in
  let open Rewriter in
  empty () >>= fun table ->
  add_nat table frame ((V4 xl), xlport) >>= function
  | Overlap -> Alcotest.fail "add_nat claimed overlap when inserting into an
                 empty table"
  | Unparseable ->
    Printf.printf "Allegedly unparseable frame follows:\n";
    Cstruct.hexdump frame;
    Alcotest.fail "add_nat claimed that a reference packet was unparseable"
  | Ok ->
    (* make sure table actually has the entries we expect *)
    assert_translates table Source frame >>= fun () ->
    let orig_frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src ~dst ~src_port ~dst_port in
    assert_payloads_match frame orig_frame;
    let reverse_frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:dst ~dst:xl
        ~src_port:dst_port ~dst_port:xlport in
    assert_translates table Destination reverse_frame >>= fun () ->
    let orig_reverse_frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:dst ~dst:xl
        ~src_port:dst_port ~dst_port:xlport in
    assert_payloads_match orig_reverse_frame reverse_frame;
    let open Rewriter in
    (* trying the same operation again should update the expiration time *)
    add_nat table orig_frame ((V4 xl), xlport) >>= function
    | Overlap -> Alcotest.fail "add_nat disallowed an update"
    | Unparseable ->
      Printf.printf "Allegedly unparseable frame follows:\n";
      Cstruct.hexdump frame;
      Alcotest.fail "add_nat claimed that a reference packet was unparseable"
    | Ok ->
      (* a half-match should fail with Overlap *)
      let frame = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:xl ~dst ~src_port ~dst_port in
      add_nat table frame ((Ipaddr.V4 xl), xlport) >>= function
      | Ok -> Alcotest.fail "overlap wasn't detected"
      | Unparseable ->
        Printf.printf "Allegedly unparseable frame follows:\n";
        Cstruct.hexdump frame;
        Alcotest.fail "add_nat claimed that a reference packet was unparseable"
      | Overlap -> Lwt.return_unit


let test_add_nat_nonsense () =
  (* TODO: also test broadcast packets, non-tcp/udp/icmp packets *)
  let open Default_values in
  let proto = Udp in
  let payload = Cstruct.of_string "SET PASV" in
  let mangled_looking = Constructors.full_packet ~payload ~proto ~ttl:52 ~src:xl ~dst ~src_port ~dst_port in
  Ipv4_wire.set_ipv4_hlen_version mangled_looking 0xff;
  let open Rewriter in
  empty () >>= fun t ->
  add_nat t mangled_looking ((Ipaddr.V4 xl), xlport) >>= function
  | Ok -> Alcotest.fail "add_nat happily took a mangled packet"
  | Overlap -> Alcotest.fail
                 "add_nat claimed a mangled packet was already in the table"
  | Unparseable -> Lwt.return_unit

let test_add_nat_broadcast () =
  let open Default_values in
  let proto = Udp in
  let broadcast_dst = ipv4_of_str "255.255.255.255" in
  let broadcast = Constructors.full_packet ~payload:(Cstruct.create 0) ~proto:Tcp ~ttl:30 ~src
                    ~dst:broadcast_dst ~src_port ~dst_port in
  let open Rewriter in
  empty () >>= fun t ->
  add_nat t broadcast ((Ipaddr.V4 xl), xlport) >>= function
  | Ok | Overlap -> Alcotest.fail "add_nat operated on a broadcast packet"
  | Unparseable ->
    (* try just an ethernet frame *)
    let e = zero_cstruct (Cstruct.create Ethif_wire.sizeof_ethernet) in
    empty () >>= fun t ->
    add_nat t e ((Ipaddr.V4 xl), xlport) >>= function
    | Ok | Overlap ->
      Alcotest.fail "add_nat claims to have succeeded with a bare ethernet frame"
    | Unparseable -> Lwt.return_unit

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
    (Constructors.full_packet ~payload:(Cstruct.create 0) ~proto:Tcp ~ttl ~src ~dst ~src_port ~dst_port, r)
  in
  (* test results are a little easier to reason about if we mimic the expected
     behaviour of users -- NATting stuff from gateway IP to another IP
     downstream from a gateway, both of which are fixed *)
  Random.self_init ();
  let fixed_internal_ip = random_ipv4 () in
  let fixed_external_ip = random_ipv4 () in
  let open Rewriter in
  empty () >>= fun t ->
  let rec shove_entries = function
    | n when n <= 0 -> Lwt.return_unit
    | n ->
      Printf.printf "%d more entries...\n%!" n;
      let (packet, values) = random_packet () in
      translate t packet >>= function
      | Translated ->
        Printf.printf "already a Source entry for the packet; trying again\n%!";
        shove_entries n (* generated an overlap; try again *)
      | Untranslated ->
        translate t packet >>= function
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
            Printf.printf "source: %s, %x\n" (print_ip values.src) values.src_port;
            Printf.printf "destination: %s, %x\n" (print_ip values.dst) values.dst_port;
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
