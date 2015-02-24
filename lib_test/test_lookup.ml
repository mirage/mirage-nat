open OUnit2
open Nat_lookup

let interior_v4 = ((Ipaddr.of_string_exn "1.2.3.4"), 6000)
let exterior_v4 = ((Ipaddr.of_string_exn "192.168.3.11"), 80)
let translate_v4 = ((Ipaddr.of_string_exn "128.128.128.128"), 45454)
let translate_right_v4 = ((Ipaddr.of_string_exn "128.128.128.128"), 4292)

let interior_v6 = ((Ipaddr.of_string_exn "10.1.2.3"), 6667)
let exterior_v6 = ((Ipaddr.of_string_exn "2a01:e35:2e8a:1e0::42:10"), 1234)
let translate_v6 = ((Ipaddr.of_string_exn
                       "2604:3400:dc1:43:216:3eff:fe85:23c5"), 20002)
let translate_right_v6 = ((Ipaddr.of_string_exn "2a01:e35:2e8a:1e0::42:10"), 4292)

let lookup_printer = function
  | None -> "none"
  | Some (left, right) -> Printf.sprintf "(%s, %d), (%s, %d)"
    (Ipaddr.to_string (fst left)) (snd left)
    (Ipaddr.to_string (fst right)) (snd right)

let show_table_entry (proto, left, right, translate, translate_right) = Printf.sprintf
    "for source NAT rewrites, protocol %d: %s -> %s" proto 
    (lookup_printer (Some (left, right))) (lookup_printer (Some (translate,
                                                                 translate_right)))

let default_table ?(mode=Nat) () =
  let or_error fn =
    match fn with
    | Some r -> r
    | None -> assert_failure "Couldn't construct test NAT table"
  in
  let t = Nat_lookup.empty () in
  let t = or_error (insert ~mode t 6 interior_v4 exterior_v4 translate_v4
                      translate_right_v4) in
  let t = or_error (insert ~mode t 17 interior_v6 exterior_v6 translate_v6 
                      translate_right_v6) in
  t

let basic_lookup_nat context =
  let t = default_table ~mode:Nat () in
  assert_equal
    (lookup t 6 interior_v4 exterior_v4) (Some (translate_v4, exterior_v4));
  assert_equal
    (lookup t 6 exterior_v4 translate_v4) (Some (exterior_v4, interior_v4));
  assert_equal
    (lookup t 17 interior_v6 exterior_v6) (Some (translate_v6, exterior_v6));
  assert_equal
    (lookup t 17 exterior_v6 translate_v6) (Some (exterior_v6, interior_v6));
  assert_equal
    (lookup t 4 interior_v4 exterior_v4) None;
  assert_equal
    (lookup t 6 ((Ipaddr.of_string_exn "8.8.8.8"), 6000) exterior_v4) None;
  assert_equal
    (lookup t 6 ((Ipaddr.of_string_exn "0.0.0.0"), 6000) exterior_v4) None

let basic_lookup_redirect context =
  let t = default_table ~mode:Redirect () in
  assert_equal ~printer:lookup_printer
    (lookup t 6 interior_v4 translate_v4) (Some (translate_right_v4, exterior_v4));
  assert_equal ~printer:lookup_printer
    (lookup t 6 exterior_v4 translate_right_v4) (Some (translate_v4, interior_v4));
  assert_equal ~printer:lookup_printer
    (lookup t 17 interior_v6 translate_v6) (Some (translate_right_v6, exterior_v6));
  assert_equal ~printer:lookup_printer
    (lookup t 17 exterior_v6 translate_right_v6) (Some (translate_v6, interior_v6));
  assert_equal ~printer:lookup_printer
    (lookup t 4 interior_v4 translate_v4) None;
  assert_equal ~printer:lookup_printer
    (lookup t 6 interior_v4 exterior_v4) None;
  assert_equal ~printer:lookup_printer
    (lookup t 6 ((Ipaddr.of_string_exn "8.8.8.8"), 6000) exterior_v4) None;
  assert_equal ~printer:lookup_printer
    (lookup t 6 ((Ipaddr.of_string_exn "0.0.0.0"), 6000) exterior_v4) None

let uniqueness context =
  let t = default_table () in
  let try_bad_insert proto pair1 pair2 pair3 pair4 =
  match insert t proto pair1 pair2 pair3 pair4 with
  | Some t -> Printf.printf "Table with duplicates: %s\n" (Nat_lookup.string_of_t t);
    assert_failure (Printf.sprintf "Insertion succeeded for duplicate
                                table entry %s" (show_table_entry (proto, pair1,
                                                                   pair2,
                                                                   pair3, pair4)))
  | None -> ()
  in
  (* two sources mapped to same dst/xl can't be disambiguated, so these should
     produce None *)
  try_bad_insert 6 ((Ipaddr.of_string_exn "192.168.3.29"), 12021) exterior_v4
    translate_v4 exterior_v4;
  try_bad_insert 17 ((Ipaddr.of_string_exn "10.1.2.4"), 6667) exterior_v6
    translate_v6 exterior_v6

let suite = "test-lookup" >:::
            [
    "basic lookups work for nat mode" >:: basic_lookup_nat;
    "basic lookups work for redirect mode" >:: basic_lookup_redirect;
    "uniqueness is enforced" >:: uniqueness
  ]

let () = run_test_tt_main suite
