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

  val empty : unit -> t Lwt.t
end

module type CLOCK = sig
  val now : unit -> int64
end

module Make(Backend: Irmin.S_MAKER)(Clock: CLOCK) = struct

  module T = Inds_table.Make(Nat_table.Key)(Nat_table.Entry)(Irmin.Path.String_list)
  module I = Irmin.Basic (Backend)(T)
  type t = (string -> I.t)

  let rec tick t =
    let expiry_check_interval = 60. in
    I.head_exn (t "starting expiry") >>= fun head ->
    I.of_head t.config (task t.owner) head >>= fun our_br ->
    I.read_exn (our_br "read for timeouts") t.node >>= fun table ->
    let now = Clock.now () |> Int64.to_int in
    let updated = T.expire table now in
    match (T.M.equal updated table) with
    | false -> 
      OS.Time.sleep expiry_check_interval >>= fun () -> tick ()
    | true ->
      I.update (our_br "tick: removed expired entries") t.node updated >>= fun () ->
      I.merge_exn "merge expiry branch" our_br ~into:t.cache >>= fun () ->
      OS.Time.sleep expiry_check_interval >>= fun () -> tick ()

  let expired time = (Clock.now () |> Int64.to_int) > time
  let owner = "friendly natbot"
  let config = Irmin_mem.config () (* both config & task need to be parameterized *)
  let task = Irmin.Task.create ~date:(Clock.now ()) ~owner
  let empty () =
    I.create config task >>= fun table ->
    I.update (table "TCP table initialization") (node Tcp) (T.empty) >>= fun () ->
    I.update (table "UDP table initialization") (node Udp) (T.empty) >>= fun () ->
    Lwt.return table

  let store_of_t t = t "read for store_of_t"

  let mem table key = T.M.mem key table

  let lookup table proto ~source ~destination =
    try
      I.read_exn (table "read for lookup") (node proto) >>= fun table ->
      match (T.find (source, destination) table) with
      | Nat_table.Entry.Confirmed (time, mapping) ->
        if (expired time) then Lwt.return None else Lwt.return (Some mapping)
    with
    | Not_found -> Lwt.return None

  let in_branch table proto ~head ~read ~update ~merge fn =
    I.head_exn (table head) >>= fun head ->
    I.of_head config task head >>= fun branch ->
    I.read (branch read) (node proto) >>= function
    | None -> Lwt.return None
    | Some map ->
      let map = T.to_map map in
      match (fn map) with
      | None -> Lwt.return None
      | Some map ->
        I.update (branch update) (node proto) (T.of_map map) >>= fun () ->
        I.merge_exn merge branch ~into:table >>= fun () -> Lwt.return (Some table)

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
