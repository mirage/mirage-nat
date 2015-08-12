(* TODO: what are the data types on protocol numbers?  no explicit
   types in tcpip/lib/ipv4.ml, just matches on the number
   straight from the struct, so we'll do that too although we
   should instead restrict to tcp or udp *)

(* TODO: types should be more complex and allow for entries mapping
   networks and port ranges (with logic disallowing many:many mappings), e.g.
   type One = port
   type Many = port list
   type mapping = [ One * One, One * Many, Many * One ]

   Doing this will cause us to need a real parser.
*)
type protocol = | Udp | Tcp
type port = int (* TODO: should probably formalize that this is uint16 *)
type endpoint = Nat_table.Endpoint.t
type mapping = (endpoint * endpoint)
type mode =
  | Redirect
  | Nat

let string_of_proto = function
  | Tcp -> "tcp"
  | Udp -> "udp"

let node proto = [ string_of_proto proto ]

let (>>=) = Lwt.bind

module type S = sig
  module I : Irmin.BASIC
  type t 

  val lookup : t -> protocol -> source:endpoint -> destination:endpoint ->
    (endpoint * endpoint) option Lwt.t

  val insert : t -> int -> protocol ->
    internal_lookup:mapping -> 
    external_lookup:mapping ->
    internal_mapping:mapping ->
    external_mapping:mapping -> t option Lwt.t

  val delete : t -> protocol ->
    internal_lookup:mapping -> external_lookup:mapping -> t Lwt.t

  val empty : Irmin.config -> t Lwt.t
end

module type CLOCK = sig
  val now : unit -> int64
end

module type TIME = sig
  val sleep : float -> unit Lwt.t
end

module Make(Backend: Irmin.S_MAKER)(Clock: CLOCK)(Time: TIME) = struct

  module T = Inds_table.Make(Nat_table.Key)(Nat_table.Entry)(Irmin.Path.String_list)
  module I = Irmin.Basic (Backend)(T)

  let owner = "friendly natbot"

  type t = {
    config: Irmin.config;
    store: (string -> I.t);
  }

  let expired time = (Clock.now () |> Int64.to_int) > time
  let task () = Irmin.Task.create ~date:(Clock.now ()) ~owner

  let rec tick t () =
    (* only do expiration for UDP, since we intend to do something state-based
       for TCP *)
    let node = node Udp in
    let expiry_check_interval = 6. in
    I.head_exn (t.store "starting expiry") >>= fun head ->
    I.of_head t.config (task ()) head >>= fun our_br ->
    I.read_exn (our_br "read for timeouts") node >>= fun table ->
    let now = Clock.now () |> Int64.to_int in
    let updated = T.expire table now in
    match (T.equal updated table) with
    | true -> Time.sleep expiry_check_interval >>= tick t
    | false ->
      let message = "tick: removed expired entries as of " ^ (string_of_int now) in
      I.update (our_br message) node updated >>= fun () ->
      I.merge_exn "merge expiry branch" our_br ~into:t.store >>= fun () ->
      Time.sleep expiry_check_interval >>= tick t

  let empty config =
    I.create config (task ()) >>= fun store ->
    I.update (store "TCP table initialization") (node Tcp) (T.empty) >>= fun () ->
    I.update (store "UDP table initialization") (node Udp) (T.empty) >>= fun () ->
    let t = {
      config;
      store;
    } in
    Lwt.async (tick t);
    Lwt.return t

  let store_of_t t = t.store "read for store_of_t"

  let mem table key = T.M.mem key table

  let lookup t proto ~source ~destination =
    try
      I.read_exn (t.store "read for lookup") (node proto) >>= fun table ->
      match (T.find (source, destination) table) with
      | Nat_table.Entry.Confirmed (time, mapping) ->
        if (expired time) then Lwt.return None else Lwt.return (Some mapping)
    with
    | Not_found -> Lwt.return None

  let in_branch t proto ~head ~read ~update ~merge fn =
    I.head_exn (t.store head) >>= fun head ->
    I.of_head t.config (task ()) head >>= fun branch ->
    I.read (branch read) (node proto) >>= function
    | None -> Lwt.return None
    | Some map ->
      let map = T.to_map map in
      match (fn map) with
      | None -> Lwt.return None
      | Some map ->
        I.update (branch update) (node proto) (T.of_map map) >>= fun () ->
        I.merge_exn merge branch ~into:t.store >>= fun () -> Lwt.return (Some t)

  (* cases that should result in a valid mapping:
     neither side is already mapped *)
  let insert table expiry_interval proto
      ~internal_lookup ~external_lookup ~internal_mapping ~external_mapping =
    let expiration = (Clock.now () |> Int64.to_int) + expiry_interval in
    let insertor (map : Nat_table.Entry.t T.M.t) = 
      let check proto (src, dst) = mem map (src, dst) in
      match (check proto internal_lookup, check proto external_lookup) with
      | true, true (* TODO: this is not quite right, because it's possible that
                      the lookups are part of differing pairs. *)
      | false, false ->
        let map = T.M.add internal_lookup
            (Nat_table.Entry.Confirmed (expiration, internal_mapping)) map in
        let map = T.M.add external_lookup
            (Nat_table.Entry.Confirmed (expiration, external_mapping)) map in
        Some map
      | _, _ -> None
    in
    in_branch table proto
      ~head:"branching to add entry"
      ~read:"reading to add entry" 
      ~update:(Printf.sprintf "add %s entry" (string_of_proto proto))
      ~merge:"merge after completing add entry"
      insertor

  let delete table proto ~internal_lookup ~external_lookup =
    let remover map = 
      let map = T.M.remove internal_lookup map in
      let map = T.M.remove external_lookup map in
      Some map
    in
    in_branch table proto
      ~head:"branching to remove entry"
      ~read:"reading to remove entry"
      ~update:(Printf.sprintf "remove %s entry" (string_of_proto proto))
      ~merge:"merge after completing remove entry"
      remover >>= fun _ -> Lwt.return table

end
