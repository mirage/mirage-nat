open OUnit2
open Nat_lookup
open Test_lib

let (>>=) = Lwt.bind

let str_of_ip = Ipaddr.of_string_exn

let expiry = 0. (* TODO: nope! *)

let interior_v4 = ((str_of_ip "1.2.3.4"), 6000)
let exterior_v4 = ((str_of_ip "192.168.3.11"), 80)
let translate_v4 = ((str_of_ip "128.128.128.128"), 45454)
let translate_right_v4 = ((str_of_ip "128.128.128.128"), 4292)

let interior_v6 = ((str_of_ip "10.1.2.3"), 6667)
let exterior_v6 = ((str_of_ip "2a01:e35:2e8a:1e0::42:10"), 1234)
let translate_v6 = ((str_of_ip
                       "2604:3400:dc1:43:216:3eff:fe85:23c5"), 20002)
let translate_right_v6 = ((str_of_ip "2a01:e35:2e8a:1e0::42:10"), 4292)

let lookup_printer = function
  | None -> "none"
  | Some (left, right) -> Printf.sprintf "(%s, %d), (%s, %d)"
    (Ipaddr.to_string (fst left)) (snd left)
    (Ipaddr.to_string (fst right)) (snd right)

let show_table_entry (proto, left, right, translate, translate_right) = Printf.sprintf
    "for source NAT rewrites, protocol %d: %s -> %s" proto
    (lookup_printer (Some (left, right))) (lookup_printer (Some (translate,
                                                                 translate_right)))

let default_table () =
  let or_error fn =
    fn >>= function
    | Some r -> Lwt.return r
    | None -> assert_failure "Couldn't construct test NAT table"
  in
  empty () >>= fun t ->
  let v4_mappings = Nat_translations.map_nat
      ~left:interior_v4 ~right:exterior_v4
      ~translate_left:translate_v4 in
  let v6_mappings = Nat_translations.map_redirect
                      ~left:interior_v6 ~right:exterior_v6
                      ~translate_left:translate_v6
                      ~translate_right:translate_right_v6 in

  or_error (insert_mappings t expiry Tcp v4_mappings) >>= fun t ->
  or_error (insert_mappings t expiry Udp v6_mappings)

let check f expected =
  let printer = function
    | Some (l, r) ->
      Printf.sprintf "Some %s, %s" (Nat_table.Endpoint.to_string l) (Nat_table.Endpoint.to_string r)
    | None -> "None"
  in
  f >>= fun result -> assert_equal ~printer expected result; Lwt.return_unit

let ipv4_lookup () =
  default_table () >>= fun t ->
  let tests = [
    Tcp, (interior_v4, exterior_v4), (Some (translate_v4, exterior_v4));
    Tcp, (exterior_v4, translate_v4), (Some (exterior_v4, interior_v4));
    Udp, (interior_v4, exterior_v4), None;
    Tcp, (((str_of_ip "8.8.8.8"), 6000), exterior_v4), None;
    Tcp, (((str_of_ip "0.0.0.0"), 6000), exterior_v4), None
  ] in
  Lwt_list.map_s (fun (proto, (source, destination), expected) ->
      check (lookup t proto ~source ~destination) expected) tests >>= fun _ ->
  Lwt.return_unit

let ipv6_lookup () =
  default_table () >>= fun t ->
  check (lookup t Udp interior_v6 translate_v6)
    (Some (translate_right_v6, exterior_v6)) >>= fun () ->
  check (lookup t Udp exterior_v6 translate_right_v6)
    (Some (translate_v6, interior_v6))

let uniqueness () =
  default_table () >>= fun t ->
  (* TODO: this probably does need to check for redirect/nat overlap problems
     and generally be a bit more robust *)
  let redundant_mappings = Nat_translations.map_nat ~left:interior_v4
      ~right:exterior_v4 ~translate_left:translate_v4 in
  insert_mappings t expiry Tcp redundant_mappings >>= function
  | None -> Lwt.return_unit
  | Some t ->
    assert_failure (Printf.sprintf "Insertion succeeded for duplicate table entry %s"
                      (show_table_entry (6, interior_v4, exterior_v4,
                                         translate_v4, translate_v4)))

let lwt_run f () = Lwt_main.run (f ())

let tests = [
    "ipv4_lookup", `Quick, lwt_run ipv4_lookup;
    "ipv6_lookup", `Quick, lwt_run ipv6_lookup;
    "uniqueness", `Quick, lwt_run uniqueness
]

let () = Alcotest.run "Mirage_nat.Nat_lookup" [ "lookup_tests", tests ]
