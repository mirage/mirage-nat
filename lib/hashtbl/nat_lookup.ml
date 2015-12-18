(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]

   Doing this will cause us to need a real parser.
*)
open Nat_types

type mode =
  | Redirect
  | Nat

let (>>=) = Lwt.bind

module type S = sig
  type t

  val lookup : t -> protocol ->
    source:endpoint ->
    destination:endpoint ->
    (int64 * mapping) option Lwt.t

  val insert : t -> int -> protocol -> translation -> t option Lwt.t

  val delete : t -> protocol ->
    internal_lookup:mapping ->
    external_lookup:mapping -> t Lwt.t

  val empty : unit -> t Lwt.t
end

module Make(Clock : CLOCK)(Time: TIME) = struct

  type t = {
    store: ((protocol * mapping), (int64 * mapping)) Hashtbl.t
  }

  let rec tick t () =
    MProf.Trace.label "Nat_lookup.tick";
    (* only do expiration for UDP, since we intend to do something state-based
       for TCP *)
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
    MProf.Trace.label "Nat_lookup.lookup.read";
    match Hashtbl.mem t.store (proto, (source, destination)) with
    | false -> Lwt.return None
    | true ->
      Lwt.return (Some (Hashtbl.find t.store (proto, (source, destination))))

  (* cases that should result in a valid mapping:
     neither side is already mapped *)
  let insert t expiry_interval proto mappings =
    MProf.Trace.label "Nat_lookup.insert";
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
