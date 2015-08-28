open Nat_types

let map_nat ~left ~right ~translate_left =
  let internal_lookup = (left, right) in
  let external_lookup = (right, translate_left) in
  let internal_mapping = (translate_left, right) in
  let external_mapping = (right, left) in
  {internal_lookup; external_lookup; internal_mapping; external_mapping}

let map_redirect ~left ~right ~translate_left ~translate_right =
  let internal_lookup = (left, translate_left) in
  let external_lookup = (right, translate_right) in
  let internal_mapping = (translate_right, right) in
  let external_mapping = (translate_left, left) in
  {internal_lookup; external_lookup; internal_mapping; external_mapping}
