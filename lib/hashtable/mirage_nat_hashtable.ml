(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]

   Doing this will cause us to need a real parser.
*)
open Mirage_nat

let (>>=) = Lwt.bind

module Storage(Clock : CLOCK)(Time: TIME) : sig
  include Mirage_nat.Lookup with type config = unit
end = struct

  type t = {
    store: ((protocol * mapping), (int64 * mapping)) Hashtbl.t
  }

  type config = unit

  let rec tick t () =
    MProf.Trace.label "Mirage_nat.tick";
    let expiry_check_interval = 6. in
    let now = Clock.now () in
    Hashtbl.iter (fun key (expiry, _) ->
        match compare expiry now with
        | n when n < 0 -> Hashtbl.remove t.store key
        | _ -> ()
      ) t.store;
    Time.sleep expiry_check_interval >>= tick t

  let empty () = Lwt.return { store = Hashtbl.create 21 } (* initial size is completely arbitrary *)

  let lookup t proto ~source ~destination =
    MProf.Trace.label "Mirage_nat_hashtable.lookup.read";
    match Hashtbl.mem t.store (proto, (source, destination)) with
    | false -> Lwt.return None
    | true ->
      Lwt.return (Some (Hashtbl.find t.store (proto, (source, destination))))

  (* cases that should result in a valid mapping:
     neither side is already mapped *)
  let insert t expiry_interval proto mappings =
    MProf.Trace.label "Mirage_nat_hashtable.insert";
    let check store proto pair =
      Hashtbl.mem store (proto, pair)
    in
    let internal_mem = check t.store proto mappings.internal_lookup in
    let external_mem = check t.store proto mappings.external_lookup in
    match internal_mem, external_mem with
    | true, true (* TODO: this is not quite right, because it's possible that
                        the lookups are part of differing pairs -- this
                        situation is pathological, but possible *)
    | false, false ->
      let expiration = Int64.add (Clock.now ()) (Int64.of_int expiry_interval) in
      Hashtbl.add t.store (proto, mappings.internal_lookup) (expiration, mappings.internal_mapping);
      Hashtbl.add t.store (proto, mappings.external_lookup) (expiration, mappings.external_mapping);
      Lwt.return (Some t)
    | _, _ -> Lwt.return None

  let delete t proto ~internal_lookup ~external_lookup =
    Hashtbl.remove t.store (proto, internal_lookup);
    Hashtbl.remove t.store (proto, external_lookup);
    Lwt.return t

end

module Make(Clock: CLOCK) (Time: TIME) = struct
  module Table = Storage(Clock)(Time)
  include Nat_rewrite.Make(Table)
end
