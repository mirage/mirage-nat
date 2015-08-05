type endpoint = Nat_lookup.endpoint
type mapping = Nat_lookup.mapping
type result = {internal_lookup: mapping;
               external_lookup: mapping;
               internal_mapping: mapping;
               external_mapping: mapping }

val map_nat : left:endpoint -> right:endpoint -> translate_left:endpoint ->
  result

val map_redirect : left:endpoint -> right:endpoint ->
  translate_left:endpoint -> translate_right:endpoint ->
  result
