open OUnit

let arbitrary_table_entry =
  let open QuickCheck_gen in
  let open QuickCheck in
  let arbitrary_ip_port = Arbitrary.(arbitrary_pair arbitrary_ip arbitrary_port) in
  Arbitrary.arbitrary_tcp_or_udp >>= fun v1 -> 
  arbitrary_ip_port >>= fun v2 ->
  arbitrary_ip_port >>= fun v3 ->
  arbitrary_ip_port >>= fun v4 ->
  arbitrary_ip_port >>= fun v5 ->
  ret_gen (v1, v2, v3, v4, v5)

let crud context =
  let module QC = QuickCheck in
  (* propositions:
  (* parseable UDP/TCP packets (and only those) result in a table insertion *)
     inserting then looking up a frame results in a valid translation *)
  (* the table is capable of handling many (~10,000, say) connections without
     the program ending abnormally *)
  let prop_nat_cruds_as_expected input (* where input is a list of random proto ->
                                          ip,port -> ip,port *) =
    let mem_bidirectional table protocol left right translate =
      let src_rewrite = lookup table protocol left right in
      let dst_rewrite = lookup table protocol right translate in
      if src_rewrite = (Some (translate, right)) && 
         dst_rewrite = (Some (right, left)) then true else false
    in
    (* add or delete a list of entries and return the populated/depopulated
       table *)
    let for_all h entries fn =
      List.fold_left (
        fun h (protocol, left, right, translate, translate_right) -> (
            match fn h protocol left right translate translate_right with
            | None ->
              let str = Test_lookup.show_table_entry (protocol, left, right, translate, translate_right) in
              assert_failure (Printf.sprintf "Couldn't work with %s" str)
            | Some t -> t
          )) h entries
    in
    let add_all h entries = for_all h entries insert in
    let remove_all h entries = for_all h entries delete in
    (* see whether it's all there as expected *)
    let all_there h entries =
      List.fold_left (fun continue (protocol, left, right, translate,
                                    translate_right) ->
                       match continue with
                       | true -> mem_bidirectional h protocol left right translate
                       | false -> false)
        true entries
    in
    let none_there h entries =
      match entries with
      | [] -> true
      | _ -> not (all_there h entries)
    in
    let adds t entries =
      let t = add_all t entries in
      (t, all_there t entries)
    in
    let deletes t entries =
      let t = remove_all t entries in
      (t, none_there t entries)
    in
    let t = empty () in
    let added, add_result = adds t input in
    let deleted, delete_result = deletes added input in
    add_result && delete_result
  in
  let arbitrary_table_entry_list =
    QC.arbitrary_list arbitrary_table_entry
  in
  let testable_entries_to_boolean = 
    QC.quickCheck (QC.testable_fun arbitrary_table_entry_list
                     (QC.show_list Test_lookup.show_table_entry)
                     QC.testable_bool)
  in
  let result = testable_entries_to_boolean prop_nat_cruds_as_expected in
  assert_equal ~printer:Arbitrary.qc_printer QC.Success result

let suite = "randomized-tests" >:::
            [
              "crud" >:: crud
              (* TODO: crud-test redirect-style entries *)
              (* TODO: test Nat_rewrite functions against arbitrary frames *)
            ]

let () = ignore (run_test_tt_main suite)
