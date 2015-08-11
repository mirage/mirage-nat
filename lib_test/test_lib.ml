module Unix_clock = struct
  let now () = Int64.of_float (Unix.time ())
end

module N = Nat_lookup.Make(Irmin_mem.Make)(Unix_clock)

let insert_mappings table expiry proto mappings =
  let open Nat_translations in
  N.insert table expiry proto
    ~internal_lookup:mappings.internal_lookup
    ~external_lookup:mappings.external_lookup
    ~internal_mapping:mappings.internal_mapping
    ~external_mapping:mappings.external_mapping
