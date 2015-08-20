open Nat_types

(* needs better name -- kill map_ here *)
val map_nat : left:endpoint -> right:endpoint -> translate_left:endpoint ->
  translation

val map_redirect : left:endpoint -> right:endpoint ->
  translate_left:endpoint -> translate_right:endpoint ->
  translation
