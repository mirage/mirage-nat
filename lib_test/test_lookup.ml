open OUnit2
open Lookup

let interior_v4 = ((Ipaddr.of_string_exn "1.2.3.4"), 6000)
let exterior_v4 = ((Ipaddr.of_string_exn "192.168.3.11"), 80)
let translate_v4 = ((Ipaddr.of_string_exn "128.128.128.128"), 45454)

let interior_v6 = ((Ipaddr.of_string_exn "10.1.2.3"), 6667)
let exterior_v6 = ((Ipaddr.of_string_exn "2a01:e35:2e8a:1e0::42:10"), 1234)
let translate_v6 = ((Ipaddr.of_string_exn
                       "2604:3400:dc1:43:216:3eff:fe85:23c5"), 20002)

let (empty_table : Lookup.table) = empty ()

let show_table_entry (proto, left, right, translate) = Printf.sprintf
    "for source rewrites, protocol %d: (%s, %d), (%s, %d) -> (%s, %d), (%s, %d)" proto 
    (Ipaddr.to_string (fst left)) (snd left)
    (Ipaddr.to_string (fst right)) (snd right)
    (Ipaddr.to_string (fst translate)) (snd translate)
    (Ipaddr.to_string (fst right)) (snd right)

let default_table () =
  let t = Hashtbl.create 20 in
  (* TODO: don't just assume success *)
  let _ = insert t 6 interior_v4 exterior_v4 translate_v4 in
  let _ = insert t 17 interior_v6 exterior_v6 translate_v6 in
  t

let basic_lookup context =
  let t = default_table () in
  assert_equal 
    (lookup t 6 interior_v4 exterior_v4) (Some translate_v4);
  assert_equal 
    (lookup t 6 exterior_v4 translate_v4) (Some interior_v4);
  assert_equal 
    (lookup t 17 interior_v6 exterior_v6) (Some translate_v6);
  assert_equal 
    (lookup t 17 exterior_v6 translate_v6) (Some interior_v6);
  assert_equal 
    (lookup t 4 interior_v4 exterior_v4) None;
  assert_equal 
    (lookup t 6 ((Ipaddr.of_string_exn "8.8.8.8"), 6000) exterior_v4) None;
  assert_equal 
    (lookup t 6 ((Ipaddr.of_string_exn "0.0.0.0"), 6000) exterior_v4) None
(* TODO: with an empty table, any randomized check does not succeed *)
(* (todo: generator of random ips/ports) *)

let crud context =
  let module QC = QuickCheck in
  (* create, update, delete work as expected *)
  (* propositions: inserting then looking up results in input being found;
     deleting then looking up results in input not being found *)
  (* ideally we'd do this as 
     "make an empty table, 
     insert a batch of random things, 
     test that they're all there and correct,
     delete all of them, 
     test that they're not there, 
     test that nothing's there" *)
  let prop_cruds_as_expected input (* where input is a list of random proto ->
                                      ip,port -> ip,port *) =
    let h = empty () in
    let mem_bidirectional table protocol left right translate =
      let src_rewrite = lookup table protocol left right in
      let dst_rewrite = lookup table protocol right translate in
      match src_rewrite, dst_rewrite with
      | Some translate, Some left -> true 
      | None, _ | _, None -> false
    in
    (* add randomly generated data to the map *)
    ignore (List.map (fun (protocol, left, right, translate) -> 
        insert h protocol left right translate) input); 
    (* see whether it's all there as expected *)
    let all_there = List.fold_left (fun continue (protocol, left, right,
                                                  translate) -> 
                                     match continue with
          | true -> mem_bidirectional h protocol left right translate
          | false -> false
        ) true input
    in
    all_there (* TODO: deletes *)
  in
  let arbitrary_table_entry_list =
    QC.arbitrary_list Arbitrary.arbitrary_table_entry
  in
  let testable_entries_to_boolean = QC.quickCheck (QC.testable_fun
                                          arbitrary_table_entry_list
                                          (QC.show_list show_table_entry)
                                          QC.testable_bool)
  in
  let result = testable_entries_to_boolean prop_cruds_as_expected in
  assert_equal ~printer:Arbitrary.qc_printer QC.Success result

let uniqueness context =
  let t = default_table () in
  let try_bad_insert proto pair1 pair2 pair3 =
  match insert t proto pair1 pair2 pair3 with
  | Some t -> assert_failure (Printf.sprintf "Insertion succeeded for duplicate
                                table entry %s" (show_table_entry (proto, pair1,
                                                                   pair2,
                                                                   pair3)))
  | None -> ()
  in
  (* two sources mapped to same dst/xl can't be disambiguated, so these should
     produce None *)
  try_bad_insert 6 ((Ipaddr.of_string_exn "192.168.3.29"), 12021) exterior_v4
    translate_v4; 
  try_bad_insert 17 ((Ipaddr.of_string_exn "10.1.2.4"), 6667) exterior_v6
    translate_v6

let suite = "test-lookup" >::: 
  [
    "basic lookups work" >:: basic_lookup;
    "crud" >:: crud;
    "uniqueness is enforced" >:: uniqueness
  ]

let () = run_test_tt_main suite
