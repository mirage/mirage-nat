(* this blank test_rewrite.mli is required for OCaml 4.04.2 to build the tests;
   without it, the typechecker fails:

   File "lib_test/test_rewrite.ml", line 7, characters 4-20:
   Error: The type of this expression,
          (Nat_packet.t, _[< Mirage_nat.error > `TTL_exceeded `Untranslated ])
          Result.result Alcotest.testable,
          contains type variables that cannot be generalized

   Before removing this apparently useless empty file, verify that tests still
   build without it present under whichever compiler versions you're supporting.
*)
