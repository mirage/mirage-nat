open OUnit2
open Nat_lookup

let str_of_ip = Ipaddr.of_string_exn

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

let insert_mappings table proto mappings =
  let open Nat_translations in
  insert table proto
    ~internal_lookup:mappings.internal_lookup
    ~external_lookup:mappings.external_lookup
    ~internal_mapping:mappings.internal_mapping
    ~external_mapping:mappings.external_mapping

let default_table () =
  let or_error fn =
    match fn with
    | Some r -> r
    | None -> assert_failure "Couldn't construct test NAT table"
  in
  let t = Nat_lookup.empty () in
  let v4_mappings = Nat_translations.map_nat
      ~left:interior_v4 ~right:exterior_v4
      ~translate_left:translate_v4 in
  let v6_mappings = Nat_translations.map_redirect
                      ~left:interior_v6 ~right:exterior_v6
                      ~translate_left:translate_v6
                      ~translate_right:translate_right_v6 in

  let t = or_error (insert_mappings t 6 v4_mappings) in
  let t = or_error (insert_mappings t 17 v6_mappings) in
  t

let basic_lookup_nat context =
  let t = default_table () in
  assert_equal
    (lookup t 6 interior_v4 exterior_v4) (Some (translate_v4, exterior_v4));
  assert_equal
    (lookup t 6 exterior_v4 translate_v4) (Some (exterior_v4, interior_v4));
  assert_equal
    (lookup t 4 interior_v4 exterior_v4) None;
  assert_equal
    (lookup t 6 ((str_of_ip "8.8.8.8"), 6000) exterior_v4) None;
  assert_equal
    (lookup t 6 ((str_of_ip "0.0.0.0"), 6000) exterior_v4) None

let basic_lookup_redirect context =
  let t = default_table () in
  assert_equal ~printer:lookup_printer
    (lookup t 17 interior_v6 translate_v6) (Some (translate_right_v6, exterior_v6));
  assert_equal ~printer:lookup_printer
    (lookup t 17 exterior_v6 translate_right_v6) (Some (translate_v6, interior_v6))

let uniqueness context =
  let t = default_table () in
  (* TODO: this probably does need to check for redirect/nat overlap problems
     and generally be a bit more robust *)
  let redundant_mappings = Nat_translations.map_nat ~left:interior_v4
      ~right:exterior_v4 ~translate_left:translate_v4 in
  match insert_mappings t 6 redundant_mappings with
  | Some t -> Printf.printf "Table with duplicates: %s\n" (Nat_lookup.string_of_t t);
    assert_failure (Printf.sprintf "Insertion succeeded for duplicate table entry %s"
                      (show_table_entry (6, interior_v4, exterior_v4,
                                         translate_v4, translate_v4)))
  | None -> ()

let suite = "test-lookup" >::: [
    "basic lookups work for nat mode" >:: basic_lookup_nat;
    "basic lookups work for redirect mode" >:: basic_lookup_redirect;
    "uniqueness is enforced" >:: uniqueness
  ]

let () = run_test_tt_main suite
