module N = Nat_lookup.Make(Irmin_mem.Make)

let insert_mappings table expiry proto mappings =
  let open Nat_translations in
  N.insert table expiry proto
    ~internal_lookup:mappings.internal_lookup
    ~external_lookup:mappings.external_lookup
    ~internal_mapping:mappings.internal_mapping
    ~external_mapping:mappings.external_mapping
