let insert_mappings table expiry proto mappings =
  let open Nat_translations in
  Nat_lookup.insert table expiry proto
    ~internal_lookup:mappings.internal_lookup
    ~external_lookup:mappings.external_lookup
    ~internal_mapping:mappings.internal_mapping
    ~external_mapping:mappings.external_mapping
